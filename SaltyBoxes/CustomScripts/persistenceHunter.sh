#!/bin/bash
# ==============================================================================
# Script Name: persistenceHunter.sh
# Description: Comprehensive check for attacker persistence mechanisms with
#              optional remediation capabilities
# Author: CCDC Team
# Date: 2025-2026
# Version: 2.1
#
# Usage:
#   ./persistenceHunter.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -r, --remediate  Enable remediation mode (quarantine, kill, disable)
#   -q, --quiet      Only show findings, not headers
#   -o, --output     Write output to specified file
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#   - Alpine Linux
#
# Exit Codes:
#   0 - Success (no critical findings or remediated)
#   1 - Critical findings detected
#   2 - Script error
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
QUARANTINE_DIR="/quarantine/persistence_hunter"
LOG_DIR="/var/log/persistence_hunter"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)

# --- Options ---
REMEDIATE=false
QUIET=false
OUTPUT_FILE=""

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Counters ---
CRITICAL_FINDINGS=0
WARNING_FINDINGS=0
INFO_FINDINGS=0

# --- Helper Functions ---
usage() {
    head -30 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

header() {
    [[ "$QUIET" == "false" ]] && echo -e "\n${CYAN}[$1]${NC} $2"
    [[ "$QUIET" == "false" ]] && echo "----------------------------------------"
}

critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
    ((CRITICAL_FINDINGS++))
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNING_FINDINGS++))
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    ((INFO_FINDINGS++))
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

remediate_msg() {
    if [[ "$REMEDIATE" == "true" ]]; then
        echo -e "${MAGENTA}[REMEDIATE]${NC} $1"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        exit 2
    fi
}

setup_quarantine() {
    if [[ "$REMEDIATE" == "true" ]]; then
        mkdir -p "$QUARANTINE_DIR"
        mkdir -p "$LOG_DIR"
        chmod 700 "$QUARANTINE_DIR" "$LOG_DIR"
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -r|--remediate)
            REMEDIATE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main Execution ---
check_root
setup_quarantine

echo "========================================"
echo "PERSISTENCE HUNTER v2.1 - $HOSTNAME"
echo "Time: $(date)"
[[ "$REMEDIATE" == "true" ]] && echo -e "${MAGENTA}REMEDIATION MODE ENABLED${NC}"
echo "========================================"

# ==============================================================================
# SECTION 1: CRON PERSISTENCE
# ==============================================================================
header "1/19" "CRON JOBS - All Users"
for user in $(cut -f1 -d: /etc/passwd); do
    cron_content=$(crontab -u "$user" -l 2>/dev/null)
    if [[ -n "$cron_content" ]]; then
        echo "  Crontab for: $user"
        echo "$cron_content" | while read -r line; do
            if echo "$line" | grep -qE "curl|wget|nc |ncat|bash -i|/dev/tcp|python|perl|php"; then
                warning "Suspicious cron entry for $user: $line"
            else
                echo "    $line"
            fi
        done
    fi
done

header "2/19" "CRON DIRECTORIES"
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d "$crondir" ]]; then
        for f in "$crondir"/*; do
            [[ -f "$f" ]] && echo "  $f"
        done
    fi
done
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$"

# ==============================================================================
# SECTION 2: SYSTEMD PERSISTENCE
# ==============================================================================
header "3/19" "SYSTEMD USER SERVICES"
find /etc/systemd/system -type f -name "*.service" -newer /etc/passwd 2>/dev/null | while read -r svc; do
    warning "Recently created service: $svc"
done
find /home -path "*/.config/systemd/user/*.service" 2>/dev/null | while read -r svc; do
    warning "User systemd service: $svc"
done

header "4/19" "SUSPICIOUS SYSTEMD SERVICES (with network connections)"
for service in $(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}'); do
    pid=$(systemctl show -p MainPID "$service" 2>/dev/null | cut -d'=' -f2)
    if [[ "$pid" != "0" && -d "/proc/$pid" ]]; then
        binary_path=$(readlink -f /proc/$pid/exe 2>/dev/null)
        established=$(ss -tnp 2>/dev/null | grep "pid=$pid" | grep -v "127.0.0.1")

        if [[ -n "$established" ]]; then
            # Check if it's a known legitimate service
            if ! echo "$service" | grep -qE "^(systemd|dbus|NetworkManager|sshd|rsyslog|cron|salt|splunk|wazuh|apache|nginx|mysql|postgresql)"; then
                warning "Service '$service' (PID $pid) has external connections:"
                echo "$established" | sed 's/^/    /'

                if [[ "$REMEDIATE" == "true" && -f "$binary_path" ]]; then
                    remediate_msg "Quarantining $service..."
                    # Log before action
                    {
                        echo "Timestamp: $(date)"
                        echo "Service: $service"
                        echo "PID: $pid"
                        echo "Binary: $binary_path"
                        echo "Connections: $established"
                        systemctl show "$service"
                    } > "$LOG_DIR/${service}_${TIMESTAMP}.log"

                    # Move binary to quarantine
                    mkdir -p "$QUARANTINE_DIR/$service"
                    cp "$binary_path" "$QUARANTINE_DIR/$service/" 2>/dev/null

                    # Stop and disable
                    systemctl stop "$service" 2>/dev/null
                    systemctl disable "$service" 2>/dev/null

                    # Kill process
                    kill -9 "$pid" 2>/dev/null
                    remediate_msg "Service $service stopped and quarantined"
                fi
            fi
        fi
    fi
done

# ==============================================================================
# SECTION 3: INIT SCRIPTS
# ==============================================================================
header "5/19" "INIT.D SCRIPTS"
ls -la /etc/init.d/ 2>/dev/null | grep -v "^total" | grep -v "README"

header "6/19" "RC.LOCAL"
for rcfile in /etc/rc.local /etc/rc.d/rc.local; do
    if [[ -f "$rcfile" ]]; then
        content=$(grep -v "^#" "$rcfile" | grep -v "^$" | grep -v "^exit 0")
        if [[ -n "$content" ]]; then
            warning "Content in $rcfile:"
            echo "$content" | sed 's/^/    /'
        fi
    fi
done

# ==============================================================================
# SECTION 4: SSH PERSISTENCE
# ==============================================================================
header "7/19" "AUTHORIZED_KEYS - All Users"
find /home -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
    user=$(echo "$keyfile" | cut -d'/' -f3)
    keycount=$(wc -l < "$keyfile")
    info "Found $keycount key(s) for user $user: $keyfile"
    cat "$keyfile" | while read -r key; do
        # Check for suspicious key comments
        if echo "$key" | grep -qiE "attacker|hacker|evil|backdoor|temp|test"; then
            warning "Suspicious SSH key comment in $keyfile"
        fi
    done
done

if [[ -f /root/.ssh/authorized_keys ]]; then
    keycount=$(wc -l < /root/.ssh/authorized_keys)
    warning "Root has $keycount authorized SSH key(s)"
fi

# ==============================================================================
# SECTION 5: SUID/SGID AND PERMISSIONS
# ==============================================================================
header "8/19" "UNUSUAL SUID/SGID BINARIES"
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | grep -vE "^/(usr|bin|sbin|lib)" | head -20 | while read -r binary; do
    critical "Unusual SUID/SGID binary: $binary"
done

header "9/19" "WORLD-WRITABLE FILES IN SYSTEM DIRS"
find /etc /usr /bin /sbin -type f -perm -002 2>/dev/null | head -20 | while read -r wfile; do
    critical "World-writable system file: $wfile"
done

# ==============================================================================
# SECTION 6: HIDDEN FILES AND DIRECTORIES
# ==============================================================================
header "10/19" "HIDDEN FILES IN /TMP, /VAR/TMP, /DEV/SHM"
find /tmp /var/tmp -name ".*" -type f 2>/dev/null | while read -r hfile; do
    warning "Hidden file: $hfile"
done

ls -la /dev/shm/ 2>/dev/null | grep -v "^total" | grep -v "^d" | while read -r line; do
    [[ -n "$line" ]] && warning "File in /dev/shm: $line"
done

# ==============================================================================
# SECTION 7: KERNEL MODULES
# ==============================================================================
header "11/19" "LOADED KERNEL MODULES (non-standard)"
lsmod 2>/dev/null | grep -vE "^(Module|ext4|xfs|nfs|overlay|bridge|ip_tables|nf_|xt_|ipt_|nft_|dm_|sd_|sr_|ahci|libata|scsi|usb|hid|i2c|drm|snd|video|thermal|acpi|battery|button|processor|fan)" | while read -r mod rest; do
    info "Loaded module: $mod"
done

# ==============================================================================
# SECTION 8: SHELL PROFILE BACKDOORS
# ==============================================================================
header "12/19" "SHELL PROFILES (Backdoors)"
profile_files="/etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc"
for user_home in /home/* /root; do
    profile_files="$profile_files $user_home/.bashrc $user_home/.bash_profile $user_home/.profile $user_home/.zshrc"
done

for pfile in $profile_files; do
    [[ -f "$pfile" ]] || continue
    if grep -lE "nc |ncat|bash -i|/dev/tcp|curl.*\|.*bash|wget.*\|.*bash|python.*-c|perl.*-e|php.*-r" "$pfile" 2>/dev/null; then
        critical "Potential backdoor in: $pfile"
        grep -nE "nc |ncat|bash -i|/dev/tcp|curl.*\|.*bash|wget.*\|.*bash|python.*-c|perl.*-e|php.*-r" "$pfile" | sed 's/^/    /'

        if [[ "$REMEDIATE" == "true" ]]; then
            remediate_msg "Backing up and cleaning $pfile"
            cp "$pfile" "$QUARANTINE_DIR/$(basename $pfile)_${TIMESTAMP}"
            # Comment out suspicious lines
            sed -i.bak -E 's/(nc |ncat|bash -i|\/dev\/tcp|curl.*\|.*bash|wget.*\|.*bash)/#QUARANTINED: \1/g' "$pfile"
        fi
    fi
done

# ==============================================================================
# SECTION 9: PAM BACKDOORS (NEW)
# ==============================================================================
header "13/19" "PAM CONFIGURATION AUDIT"

# Check for pam_exec.so (command execution on auth)
pam_exec_files=$(grep -r "pam_exec.so" /etc/pam.d/ 2>/dev/null)
if [[ -n "$pam_exec_files" ]]; then
    critical "pam_exec.so found (allows command execution on auth):"
    echo "$pam_exec_files" | sed 's/^/    /'
fi

# Check for nullok (empty passwords allowed)
nullok_files=$(grep -r "nullok" /etc/pam.d/ 2>/dev/null)
if [[ -n "$nullok_files" ]]; then
    warning "nullok found (empty passwords allowed):"
    echo "$nullok_files" | sed 's/^/    /'
fi

# Check pam_permit.so / pam_deny.so order (auth bypass)
for authfile in /etc/pam.d/*-auth /etc/pam.d/common-auth /etc/pam.d/system-auth; do
    [[ -f "$authfile" ]] || continue

    deny_line=$(grep -n 'pam_deny.so' "$authfile" 2>/dev/null | cut -d: -f1 | head -n 1)
    permit_line=$(grep -n 'pam_permit.so' "$authfile" 2>/dev/null | cut -d: -f1 | head -n 1)

    if [[ -z "$permit_line" ]]; then
        warning "pam_permit.so not found in $authfile - investigate!"
    elif [[ -z "$deny_line" ]]; then
        warning "pam_deny.so not found in $authfile - investigate!"
    elif [[ "$permit_line" -lt "$deny_line" ]]; then
        critical "pam_permit.so comes BEFORE pam_deny.so in $authfile - possible auth bypass!"
    fi
done

# Check if PAM modules have been tampered with
for pam_mod in pam_deny.so pam_permit.so pam_unix.so; do
    mod_path=$(find /lib /lib64 /usr/lib /usr/lib64 -name "$pam_mod" 2>/dev/null | head -1)
    if [[ -n "$mod_path" ]]; then
        # Check if it's a valid ELF binary
        if ! file "$mod_path" | grep -q "ELF"; then
            critical "$pam_mod appears to be tampered with (not a valid ELF binary)"
        fi
    fi
done

# ==============================================================================
# SECTION 10: LD_PRELOAD ROOTKIT CHECK (NEW)
# ==============================================================================
header "14/19" "LD_PRELOAD ROOTKIT CHECK"

# Direct check of ld.so.preload
if [[ -s /etc/ld.so.preload ]]; then
    critical "/etc/ld.so.preload contains entries (possible rootkit):"
    cat /etc/ld.so.preload | sed 's/^/    /'

    if [[ "$REMEDIATE" == "true" ]]; then
        remediate_msg "Backing up and clearing ld.so.preload"
        cp /etc/ld.so.preload "$QUARANTINE_DIR/ld.so.preload_${TIMESTAMP}"
        echo "" > /etc/ld.so.preload
    fi
else
    success "ld.so.preload is empty or doesn't exist"
fi

# Chroot-based check to bypass potential LD_PRELOAD hooks
CHROOT_DIR="/tmp/.rootkit_check_$$"
if mkdir -p "$CHROOT_DIR"/{bin,lib,lib64,etc} 2>/dev/null; then
    # Copy minimal binaries
    cp /bin/cat "$CHROOT_DIR/bin/" 2>/dev/null

    # Copy required libraries
    for lib in $(ldd /bin/cat 2>/dev/null | grep -v dynamic | awk '{print $3}' | grep -v "^$"); do
        [[ -f "$lib" ]] && cp "$lib" "$CHROOT_DIR/lib/" 2>/dev/null
    done
    cp /lib64/ld-linux-x86-64.so.2 "$CHROOT_DIR/lib64/" 2>/dev/null
    cp /lib/ld-linux*.so* "$CHROOT_DIR/lib/" 2>/dev/null

    # Copy ld.so.preload for comparison
    cp /etc/ld.so.preload "$CHROOT_DIR/etc/" 2>/dev/null

    # Check from inside chroot
    chroot_result=$(chroot "$CHROOT_DIR" /bin/cat /etc/ld.so.preload 2>/dev/null)
    if [[ -n "$chroot_result" ]]; then
        critical "Chroot check confirms ld.so.preload content: $chroot_result"
    fi

    # Cleanup
    rm -rf "$CHROOT_DIR" 2>/dev/null
fi

# Check LD_PRELOAD environment variable
env_preload=$(env | grep LD_PRELOAD)
if [[ -n "$env_preload" ]]; then
    critical "LD_PRELOAD environment variable set: $env_preload"
fi

# ==============================================================================
# SECTION 11: PING SHELL / RAW SOCKET DETECTION (NEW)
# ==============================================================================
header "15/19" "RAW SOCKET / PING SHELL DETECTION"

# Check for processes with raw sockets
raw_link=$(ss -a -p -f link 2>/dev/null | grep -v "^Netid")
if [[ -n "$raw_link" ]]; then
    warning "Processes with link-layer (raw) sockets:"
    echo "$raw_link" | sed 's/^/    /'
fi

raw_vsock=$(ss -a -p -f vsock 2>/dev/null | grep -v "^Netid")
if [[ -n "$raw_vsock" ]]; then
    warning "Processes with vsock sockets:"
    echo "$raw_vsock" | sed 's/^/    /'
fi

raw_xdp=$(ss -a -p -f xdp 2>/dev/null | grep -v "^Netid")
if [[ -n "$raw_xdp" ]]; then
    critical "Processes with XDP sockets (potential packet capture/injection):"
    echo "$raw_xdp" | sed 's/^/    /'
fi

# Check for ICMP listeners
icmp_procs=$(find /proc -maxdepth 2 -name "net" 2>/dev/null | while read -r netdir; do
    pid=$(echo "$netdir" | cut -d'/' -f3)
    if [[ -f "/proc/$pid/net/raw" ]]; then
        raw_content=$(cat "/proc/$pid/net/raw" 2>/dev/null | grep -v "sl" | grep -v "^  ")
        if [[ -n "$raw_content" ]]; then
            comm=$(cat "/proc/$pid/comm" 2>/dev/null)
            echo "PID $pid ($comm)"
        fi
    fi
done | sort -u)

if [[ -n "$icmp_procs" ]]; then
    warning "Processes with raw socket access:"
    echo "$icmp_procs" | sed 's/^/    /'
fi

# ==============================================================================
# SECTION 12: C2 BEACON / IMPLANT DETECTION (NEW)
# ==============================================================================
header "16/19" "C2 IMPLANT DETECTION"

# Known C2 patterns in process binaries
c2_patterns="sliver|/usr/local/go|beacon|meterpreter|cobaltstrike|empire|havoc|mythic|posh|grunt"

# Check running process binaries
for exe in /proc/*/exe; do
    [[ -L "$exe" ]] || continue
    binary=$(readlink -f "$exe" 2>/dev/null)
    [[ -f "$binary" ]] || continue
    pid=$(echo "$exe" | cut -d'/' -f3)

    # Check binary path for Go runtime (common in Sliver, etc.)
    if echo "$binary" | grep -qiE "$c2_patterns"; then
        critical "Potential C2 binary (path match): PID $pid - $binary"
    fi

    # String check in binary (quick scan of first 1MB)
    if head -c 1048576 "$binary" 2>/dev/null | strings 2>/dev/null | grep -qiE "sliver|beacon.*http|meterpreter"; then
        critical "Potential C2 binary (string match): PID $pid - $binary"

        if [[ "$REMEDIATE" == "true" ]]; then
            remediate_msg "Killing suspected C2 process $pid"
            comm=$(cat "/proc/$pid/comm" 2>/dev/null)
            cp "$binary" "$QUARANTINE_DIR/${comm}_${pid}_${TIMESTAMP}" 2>/dev/null
            kill -9 "$pid" 2>/dev/null
        fi
    fi
done

# Check for suspicious Go binaries with network connections
for pid in $(pgrep -f ""); do
    [[ -d "/proc/$pid" ]] || continue
    binary=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    [[ -f "$binary" ]] || continue

    # Check if it's a Go binary with external connections
    if file "$binary" 2>/dev/null | grep -q "Go BuildID"; then
        connections=$(ss -tnp 2>/dev/null | grep "pid=$pid" | grep -v "127.0.0.1" | grep -v "::1")
        if [[ -n "$connections" ]]; then
            warning "Go binary with external connections: PID $pid - $binary"
            echo "$connections" | sed 's/^/    /'
        fi
    fi
done

# ==============================================================================
# SECTION 13: USERS AND AUTHENTICATION
# ==============================================================================
header "17/19" "SUSPICIOUS USERS"

# UID 0 accounts (besides root)
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read -r user; do
    critical "Non-root user with UID 0: $user"
done

# Users with no password
awk -F: '($2 == "" || $2 == "!" || $2 == "*") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null | while read -r user; do
    # Check if it's a system account
    uid=$(id -u "$user" 2>/dev/null)
    if [[ -n "$uid" && "$uid" -ge 1000 ]]; then
        warning "User with no/locked password: $user"
    fi
done

# Recently created users
find /home -maxdepth 1 -type d -mtime -7 2>/dev/null | while read -r homedir; do
    user=$(basename "$homedir")
    if id "$user" &>/dev/null; then
        info "Recently created home directory: $homedir"
    fi
done

# ==============================================================================
# SECTION 14: NETWORK LISTENERS
# ==============================================================================
header "18/19" "SUSPICIOUS NETWORK LISTENERS"

# Common backdoor ports
suspicious_ports="4444|5555|6666|1337|31337|12345|54321|9001|9002|8888|6667|6697"
ss -tlnp 2>/dev/null | grep -E ":($suspicious_ports)\s" | while read -r line; do
    warning "Listener on suspicious port: $line"
done

# Processes listening on all interfaces
ss -tlnp 2>/dev/null | grep "0.0.0.0:" | grep -v "127.0.0.1" | while read -r line; do
    port=$(echo "$line" | awk '{print $4}' | cut -d':' -f2)
    proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+')
    if ! echo "$proc" | grep -qE "sshd|apache|nginx|httpd|mysqld|postgres|splunk|salt"; then
        info "Non-standard service listening on all interfaces: $proc (port $port)"
    fi
done

# ==============================================================================
# SECTION 15: ACTIVE REVERSE SHELLS AND SUSPICIOUS PROCESSES (SHELLKILL)
# ==============================================================================
header "19/19" "REVERSE SHELLS AND SUSPICIOUS INTERACTIVE PROCESSES"

# Current user's TTY to avoid killing ourselves
CURRENT_TTY=$(tty 2>/dev/null | sed 's|/dev/||' || echo "unknown")
CURRENT_PID=$$
PARENT_PID=$PPID
KILLED_COUNT=0

# Suspicious shell interpreters that might be reverse shells
suspicious_interpreters="python|python3|perl|php|ruby|lua|node|nc|ncat|netcat|socat|telnet"

# Find processes with network connections running suspicious interpreters
while read -r line; do
    [[ -z "$line" ]] && continue
    pid=$(echo "$line" | awk '{print $1}')
    comm=$(echo "$line" | awk '{print $2}')

    # Skip our own process tree
    [[ "$pid" == "$CURRENT_PID" || "$pid" == "$PARENT_PID" ]] && continue

    # Check if this process has established network connections
    connections=$(ss -tnp 2>/dev/null | grep "pid=$pid," | grep -v "127.0.0.1" | grep -v "::1")

    if [[ -n "$connections" ]]; then
        warning "Suspicious interpreter with network connection: PID $pid ($comm)"
        echo "$connections" | sed 's/^/    /'

        if [[ "$REMEDIATE" == "true" ]]; then
            remediate_msg "Killing suspicious shell process $pid ($comm)"
            kill -9 "$pid" 2>/dev/null && ((KILLED_COUNT++))
        fi
    fi
done < <(ps -eo pid,comm | grep -E "$suspicious_interpreters" 2>/dev/null)

# Find bash/sh processes with -i flag (interactive) that have network connections
while read -r pid; do
    [[ -z "$pid" ]] && continue
    [[ "$pid" == "$CURRENT_PID" || "$pid" == "$PARENT_PID" ]] && continue

    # Get command line
    cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')

    # Check for interactive shells with network
    if echo "$cmdline" | grep -qE "(bash|sh|dash|zsh|ksh).*-i"; then
        connections=$(ss -tnp 2>/dev/null | grep "pid=$pid," | grep -v "127.0.0.1")
        if [[ -n "$connections" ]]; then
            critical "Interactive shell with network connection: PID $pid"
            echo "    Command: $cmdline"
            echo "$connections" | sed 's/^/    /'

            if [[ "$REMEDIATE" == "true" ]]; then
                remediate_msg "Killing interactive shell $pid"
                kill -9 "$pid" 2>/dev/null && ((KILLED_COUNT++))
            fi
        fi
    fi
done < <(pgrep -f "bash|sh|dash|zsh|ksh" 2>/dev/null)

# Find processes using /dev/tcp or /dev/udp
for pid in /proc/[0-9]*/fd/*; do
    [[ -L "$pid" ]] || continue
    target=$(readlink "$pid" 2>/dev/null)
    if echo "$target" | grep -qE "socket:|pipe:"; then
        proc_pid=$(echo "$pid" | cut -d'/' -f3)
        [[ "$proc_pid" == "$CURRENT_PID" || "$proc_pid" == "$PARENT_PID" ]] && continue

        # Check if process has bash with network redirection
        cmdline=$(cat /proc/$proc_pid/cmdline 2>/dev/null | tr '\0' ' ')
        if echo "$cmdline" | grep -qE "/dev/(tcp|udp)/"; then
            critical "Process using /dev/tcp or /dev/udp: PID $proc_pid"
            echo "    Command: $cmdline"

            if [[ "$REMEDIATE" == "true" ]]; then
                remediate_msg "Killing /dev/tcp process $proc_pid"
                kill -9 "$proc_pid" 2>/dev/null && ((KILLED_COUNT++))
            fi
        fi
    fi
done 2>/dev/null

# Summary of shell kills
if [[ "$REMEDIATE" == "true" && $KILLED_COUNT -gt 0 ]]; then
    remediate_msg "Killed $KILLED_COUNT suspicious shell processes"
fi

# ==============================================================================
# SUMMARY
# ==============================================================================
echo ""
echo "========================================"
echo "PERSISTENCE HUNT COMPLETE"
echo "========================================"
echo -e "Critical findings: ${RED}$CRITICAL_FINDINGS${NC}"
echo -e "Warnings:          ${YELLOW}$WARNING_FINDINGS${NC}"
echo -e "Info:              ${BLUE}$INFO_FINDINGS${NC}"

if [[ "$REMEDIATE" == "true" ]]; then
    echo ""
    echo -e "${MAGENTA}Quarantine directory: $QUARANTINE_DIR${NC}"
    echo -e "${MAGENTA}Log directory: $LOG_DIR${NC}"
fi

echo "========================================"

# Exit with appropriate code
if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
    exit 1
else
    exit 0
fi
