#!/bin/bash
# ==============================================================================
# Forensic Artifact Collector - Linux
# Comprehensive collection of system state and forensic artifacts
# For Salt-GUI / CCDC Competition Use
#
# Author: Salt-GUI Team
# License: MIT
#
# This script collects:
#   - System state (volatile): processes, network, memory info
#   - Persistence mechanisms: cron, systemd, init, shell profiles
#   - User artifacts: passwd, shadow, sudoers, SSH keys, histories
#   - Logs: auth, syslog, audit, application logs
#   - Network configuration: interfaces, routes, firewall, DNS
#   - Package information: installed packages, verification
#
# Usage:
#   ./collector.sh [output_dir] [hostname] [timestamp]
#
# Output:
#   Creates a tarball: <hostname>_forensics_<timestamp>.tar.gz
# ==============================================================================

set -uo pipefail

# Configuration
MAX_LOG_SIZE_MB=50
COMMAND_TIMEOUT=30
COLLECTION_TIMEOUT=600

# Parse arguments with defaults
OUTPUT_DIR="${1:-/tmp/forensics}"
HOSTNAME="${2:-$(hostname -s)}"
TIMESTAMP="${3:-$(date +%Y%m%d_%H%M%S)}"

# Derived paths
COLLECTION_DIR="${OUTPUT_DIR}/${HOSTNAME}_forensics_${TIMESTAMP}"
TARBALL="${OUTPUT_DIR}/${HOSTNAME}_forensics_${TIMESTAMP}.tar.gz"
METADATA_FILE="${COLLECTION_DIR}/metadata.json"

# Colors for output (disabled if not a TTY)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    NC=''
fi

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Run command with timeout, capture output, don't fail on error
safe_run() {
    local output_file="$1"
    local description="$2"
    shift 2

    log_info "Collecting: $description"
    if timeout "${COMMAND_TIMEOUT}" "$@" > "$output_file" 2>&1; then
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "# Command timed out after ${COMMAND_TIMEOUT}s" >> "$output_file"
            log_warn "Timeout: $description"
        else
            echo "# Command exited with code $exit_code" >> "$output_file"
        fi
        return 0  # Don't fail collection
    fi
}

# Copy file with size limit
safe_copy() {
    local src="$1"
    local dest="$2"
    local max_size="${3:-$((MAX_LOG_SIZE_MB * 1024 * 1024))}"

    if [ -f "$src" ]; then
        local size=$(stat -c%s "$src" 2>/dev/null || echo 0)
        if [ "$size" -gt "$max_size" ]; then
            # Copy last MAX_LOG_SIZE_MB
            tail -c "$max_size" "$src" > "$dest"
            echo "# File truncated to last $((max_size / 1024 / 1024))MB" | cat - "$dest" > "${dest}.tmp" && mv "${dest}.tmp" "$dest"
            log_warn "Truncated: $src (was ${size} bytes)"
        else
            cp "$src" "$dest" 2>/dev/null
        fi
        return 0
    else
        return 1
    fi
}

# Copy directory contents
safe_copy_dir() {
    local src="$1"
    local dest="$2"

    if [ -d "$src" ]; then
        mkdir -p "$dest"
        cp -r "$src"/* "$dest"/ 2>/dev/null || true
        return 0
    fi
    return 1
}

# Detect OS family
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# ==============================================================================
# MAIN COLLECTION
# ==============================================================================

main() {
    local start_time=$(date +%s)
    local os_family=$(detect_os)

    echo "========================================"
    echo "FORENSIC ARTIFACT COLLECTOR"
    echo "Host: ${HOSTNAME}"
    echo "Time: $(date)"
    echo "OS Family: ${os_family}"
    echo "Output: ${TARBALL}"
    echo "========================================"

    # Create directory structure
    mkdir -p "${COLLECTION_DIR}"/{system,processes,network,persistence,users,logs,shell,packages,files}
    mkdir -p "${COLLECTION_DIR}/persistence"/{cron,systemd,init.d}
    mkdir -p "${COLLECTION_DIR}/users/ssh_keys"
    mkdir -p "${COLLECTION_DIR}/shell"/{profiles,histories}

    # ======================================================================
    # SYSTEM INFORMATION (Section 1)
    # ======================================================================
    log_info "=== SYSTEM INFORMATION ==="

    safe_run "${COLLECTION_DIR}/system/hostname" "hostname" hostname
    safe_run "${COLLECTION_DIR}/system/hostname_fqdn" "hostname FQDN" hostname -f
    safe_run "${COLLECTION_DIR}/system/uname.txt" "uname" uname -a
    safe_run "${COLLECTION_DIR}/system/uptime.txt" "uptime" uptime
    safe_run "${COLLECTION_DIR}/system/date.txt" "date" date
    safe_run "${COLLECTION_DIR}/system/timezone.txt" "timezone" cat /etc/timezone
    safe_copy /etc/os-release "${COLLECTION_DIR}/system/os-release"
    safe_run "${COLLECTION_DIR}/system/kernel_cmdline.txt" "kernel cmdline" cat /proc/cmdline
    safe_run "${COLLECTION_DIR}/system/lsmod.txt" "loaded modules" lsmod
    safe_run "${COLLECTION_DIR}/system/mount.txt" "mounted filesystems" mount
    safe_run "${COLLECTION_DIR}/system/df.txt" "disk usage" df -h
    safe_run "${COLLECTION_DIR}/system/free.txt" "memory" free -h
    safe_run "${COLLECTION_DIR}/system/dmesg_tail.txt" "dmesg (last 500 lines)" dmesg -T | tail -500
    safe_copy /etc/fstab "${COLLECTION_DIR}/system/fstab"
    safe_copy /etc/mtab "${COLLECTION_DIR}/system/mtab"

    # Environment variables
    safe_run "${COLLECTION_DIR}/system/env.txt" "environment" env

    # ======================================================================
    # PROCESSES (Section 2) - VOLATILE
    # ======================================================================
    log_info "=== PROCESSES (VOLATILE) ==="

    safe_run "${COLLECTION_DIR}/processes/ps_aux.txt" "all processes" ps auxwwf
    safe_run "${COLLECTION_DIR}/processes/ps_tree.txt" "process tree" pstree -p
    safe_run "${COLLECTION_DIR}/processes/ps_threads.txt" "threads" ps -eLf
    safe_run "${COLLECTION_DIR}/processes/top.txt" "top snapshot" top -bn1

    # Open files - can be slow
    log_info "Collecting: open files (may take time)"
    timeout 60 lsof -n 2>/dev/null | head -10000 > "${COLLECTION_DIR}/processes/lsof.txt" || true

    # /proc information
    safe_run "${COLLECTION_DIR}/processes/proc_loadavg.txt" "load average" cat /proc/loadavg

    # ======================================================================
    # NETWORK (Section 3) - VOLATILE
    # ======================================================================
    log_info "=== NETWORK (VOLATILE) ==="

    # Active connections
    safe_run "${COLLECTION_DIR}/network/ss_tulpan.txt" "socket statistics" ss -tulpan
    safe_run "${COLLECTION_DIR}/network/ss_all.txt" "all sockets" ss -anp

    # Fallback to netstat if ss not available
    if ! command -v ss &>/dev/null; then
        safe_run "${COLLECTION_DIR}/network/netstat.txt" "netstat" netstat -tulpan
    fi

    # IP configuration
    safe_run "${COLLECTION_DIR}/network/ip_addr.txt" "IP addresses" ip addr
    safe_run "${COLLECTION_DIR}/network/ip_route.txt" "routing table" ip route
    safe_run "${COLLECTION_DIR}/network/ip_neigh.txt" "ARP table" ip neigh
    safe_run "${COLLECTION_DIR}/network/ip_link.txt" "network interfaces" ip link

    # DNS
    safe_copy /etc/hosts "${COLLECTION_DIR}/network/hosts"
    safe_copy /etc/resolv.conf "${COLLECTION_DIR}/network/resolv.conf"
    safe_copy /etc/nsswitch.conf "${COLLECTION_DIR}/network/nsswitch.conf"

    # Firewall rules
    if command -v iptables &>/dev/null; then
        safe_run "${COLLECTION_DIR}/network/iptables.txt" "iptables rules" iptables-save
        safe_run "${COLLECTION_DIR}/network/ip6tables.txt" "ip6tables rules" ip6tables-save
    fi
    if command -v nft &>/dev/null; then
        safe_run "${COLLECTION_DIR}/network/nftables.txt" "nftables rules" nft list ruleset
    fi
    if command -v firewall-cmd &>/dev/null; then
        safe_run "${COLLECTION_DIR}/network/firewalld.txt" "firewalld" firewall-cmd --list-all
    fi
    if command -v ufw &>/dev/null; then
        safe_run "${COLLECTION_DIR}/network/ufw.txt" "ufw status" ufw status verbose
    fi

    # ======================================================================
    # PERSISTENCE MECHANISMS (Section 4)
    # ======================================================================
    log_info "=== PERSISTENCE MECHANISMS ==="

    # CRON
    log_info "Collecting: cron jobs"

    # System crontab
    safe_copy /etc/crontab "${COLLECTION_DIR}/persistence/cron/crontab"

    # Cron directories
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$crondir" ]; then
            dirname=$(basename "$crondir")
            mkdir -p "${COLLECTION_DIR}/persistence/cron/${dirname}"
            cp -r "$crondir"/* "${COLLECTION_DIR}/persistence/cron/${dirname}/" 2>/dev/null || true
        fi
    done

    # User crontabs
    {
        echo "# User crontabs collected at $(date)"
        for user in $(cut -f1 -d: /etc/passwd); do
            crontab_output=$(crontab -u "$user" -l 2>/dev/null)
            if [ -n "$crontab_output" ]; then
                echo ""
                echo "=== Crontab for: $user ==="
                echo "$crontab_output"
            fi
        done
    } > "${COLLECTION_DIR}/persistence/cron/user_crontabs.txt"

    # SYSTEMD SERVICES
    log_info "Collecting: systemd services"

    safe_run "${COLLECTION_DIR}/persistence/systemd/services_enabled.txt" "enabled services" \
        systemctl list-unit-files --type=service --state=enabled
    safe_run "${COLLECTION_DIR}/persistence/systemd/services_running.txt" "running services" \
        systemctl list-units --type=service --state=running
    safe_run "${COLLECTION_DIR}/persistence/systemd/timers.txt" "timers" \
        systemctl list-timers --all

    # Copy custom/user service files
    mkdir -p "${COLLECTION_DIR}/persistence/systemd/custom_services"
    find /etc/systemd/system -maxdepth 1 -type f -name "*.service" -exec cp {} "${COLLECTION_DIR}/persistence/systemd/custom_services/" \; 2>/dev/null || true

    # User systemd services
    find /home -path "*/.config/systemd/user/*.service" -exec cp {} "${COLLECTION_DIR}/persistence/systemd/custom_services/" \; 2>/dev/null || true
    find /root -path "*/.config/systemd/user/*.service" -exec cp {} "${COLLECTION_DIR}/persistence/systemd/custom_services/" \; 2>/dev/null || true

    # INIT.D
    log_info "Collecting: init.d scripts"
    ls -la /etc/init.d/ > "${COLLECTION_DIR}/persistence/init.d/listing.txt" 2>/dev/null || true

    # RC.LOCAL
    log_info "Collecting: rc.local"
    safe_copy /etc/rc.local "${COLLECTION_DIR}/persistence/rc.local"
    safe_copy /etc/rc.d/rc.local "${COLLECTION_DIR}/persistence/rc.d_rc.local"

    # LD.SO.PRELOAD - Critical rootkit indicator
    log_info "Collecting: ld.so.preload"
    if [ -f /etc/ld.so.preload ]; then
        cp /etc/ld.so.preload "${COLLECTION_DIR}/persistence/ld.so.preload"
        log_warn "ld.so.preload exists - potential rootkit indicator!"
    else
        echo "# File does not exist (normal)" > "${COLLECTION_DIR}/persistence/ld.so.preload"
    fi
    safe_copy /etc/ld.so.conf "${COLLECTION_DIR}/persistence/ld.so.conf"

    # AT JOBS
    log_info "Collecting: at jobs"
    if command -v atq &>/dev/null; then
        safe_run "${COLLECTION_DIR}/persistence/at_jobs.txt" "at jobs" atq
    fi

    # ======================================================================
    # USER ARTIFACTS (Section 5)
    # ======================================================================
    log_info "=== USER ARTIFACTS ==="

    # Core user files
    safe_copy /etc/passwd "${COLLECTION_DIR}/users/passwd"
    safe_copy /etc/shadow "${COLLECTION_DIR}/users/shadow"
    safe_copy /etc/group "${COLLECTION_DIR}/users/group"
    safe_copy /etc/gshadow "${COLLECTION_DIR}/users/gshadow"

    # Sudoers
    safe_copy /etc/sudoers "${COLLECTION_DIR}/users/sudoers"
    if [ -d /etc/sudoers.d ]; then
        mkdir -p "${COLLECTION_DIR}/users/sudoers.d"
        cp -r /etc/sudoers.d/* "${COLLECTION_DIR}/users/sudoers.d/" 2>/dev/null || true
    fi

    # Login info
    safe_run "${COLLECTION_DIR}/users/last.txt" "last logins" last -100
    safe_run "${COLLECTION_DIR}/users/lastb.txt" "failed logins" lastb -100
    safe_run "${COLLECTION_DIR}/users/lastlog.txt" "lastlog" lastlog
    safe_run "${COLLECTION_DIR}/users/who.txt" "who" who -a
    safe_run "${COLLECTION_DIR}/users/w.txt" "w" w

    # SSH Keys - All users
    log_info "Collecting: SSH authorized keys"
    {
        echo "# SSH authorized_keys collected at $(date)"

        # Root
        if [ -f /root/.ssh/authorized_keys ]; then
            echo ""
            echo "=== /root/.ssh/authorized_keys ==="
            cat /root/.ssh/authorized_keys 2>/dev/null
        fi

        # All users in /home
        for homedir in /home/*; do
            if [ -f "$homedir/.ssh/authorized_keys" ]; then
                echo ""
                echo "=== $homedir/.ssh/authorized_keys ==="
                cat "$homedir/.ssh/authorized_keys" 2>/dev/null
            fi
        done
    } > "${COLLECTION_DIR}/users/ssh_keys/authorized_keys_all.txt"

    # SSH known_hosts
    {
        echo "# SSH known_hosts collected at $(date)"

        for sshdir in /root/.ssh /home/*/.ssh; do
            if [ -f "$sshdir/known_hosts" ]; then
                echo ""
                echo "=== $sshdir/known_hosts ==="
                cat "$sshdir/known_hosts" 2>/dev/null
            fi
        done
    } > "${COLLECTION_DIR}/users/ssh_keys/known_hosts_all.txt"

    # ======================================================================
    # SHELL PROFILES & HISTORIES (Section 6)
    # ======================================================================
    log_info "=== SHELL PROFILES & HISTORIES ==="

    # System-wide profiles
    safe_copy /etc/profile "${COLLECTION_DIR}/shell/profiles/etc_profile"
    safe_copy /etc/bash.bashrc "${COLLECTION_DIR}/shell/profiles/etc_bash.bashrc"
    safe_copy /etc/bashrc "${COLLECTION_DIR}/shell/profiles/etc_bashrc"

    # Profile.d directory - common backdoor location
    if [ -d /etc/profile.d ]; then
        mkdir -p "${COLLECTION_DIR}/shell/profiles/profile.d"
        cp -r /etc/profile.d/* "${COLLECTION_DIR}/shell/profiles/profile.d/" 2>/dev/null || true
    fi

    # User profiles and histories
    log_info "Collecting: user shell histories"
    for homedir in /root /home/*; do
        username=$(basename "$homedir")

        # Shell profiles
        for profile in .bashrc .bash_profile .profile .zshrc; do
            if [ -f "$homedir/$profile" ]; then
                safe_copy "$homedir/$profile" "${COLLECTION_DIR}/shell/profiles/${username}_${profile}"
            fi
        done

        # Shell histories
        for history in .bash_history .zsh_history .sh_history; do
            if [ -f "$homedir/$history" ]; then
                # Limit history to last 10000 lines
                tail -10000 "$homedir/$history" > "${COLLECTION_DIR}/shell/histories/${username}_${history}" 2>/dev/null || true
            fi
        done
    done

    # ======================================================================
    # LOGS (Section 7)
    # ======================================================================
    log_info "=== LOGS ==="

    # Auth logs - Critical for intrusion detection
    for authlog in /var/log/auth.log /var/log/secure; do
        if [ -f "$authlog" ]; then
            safe_copy "$authlog" "${COLLECTION_DIR}/logs/$(basename $authlog)"
        fi
    done

    # Syslog
    for syslog in /var/log/syslog /var/log/messages; do
        if [ -f "$syslog" ]; then
            safe_copy "$syslog" "${COLLECTION_DIR}/logs/$(basename $syslog)"
        fi
    done

    # Audit logs
    if [ -d /var/log/audit ]; then
        mkdir -p "${COLLECTION_DIR}/logs/audit"
        for auditlog in /var/log/audit/audit.log*; do
            if [ -f "$auditlog" ]; then
                safe_copy "$auditlog" "${COLLECTION_DIR}/logs/audit/$(basename $auditlog)"
            fi
        done
    fi

    # Application logs
    for applog in /var/log/apache2/access.log /var/log/apache2/error.log \
                  /var/log/httpd/access_log /var/log/httpd/error_log \
                  /var/log/nginx/access.log /var/log/nginx/error.log \
                  /var/log/mysql/error.log /var/log/mysqld.log \
                  /var/log/fail2ban.log /var/log/ufw.log; do
        if [ -f "$applog" ]; then
            appname=$(dirname "$applog" | xargs basename)
            logname=$(basename "$applog")
            safe_copy "$applog" "${COLLECTION_DIR}/logs/${appname}_${logname}"
        fi
    done

    # Journal (last 10000 lines)
    if command -v journalctl &>/dev/null; then
        safe_run "${COLLECTION_DIR}/logs/journalctl.txt" "journal (last 10000)" \
            journalctl -n 10000 --no-pager
    fi

    # Salt minion log
    safe_copy /var/log/salt/minion "${COLLECTION_DIR}/logs/salt_minion.log"

    # ======================================================================
    # PACKAGES (Section 8)
    # ======================================================================
    log_info "=== PACKAGES ==="

    case "$os_family" in
        ubuntu|debian)
            safe_run "${COLLECTION_DIR}/packages/installed_packages.txt" "installed packages" dpkg -l
            safe_run "${COLLECTION_DIR}/packages/recent_packages.txt" "recently installed" \
                grep " install " /var/log/dpkg.log 2>/dev/null | tail -100
            # Package verification can be slow
            log_info "Collecting: package verification (may take time)"
            timeout 120 debsums -s 2>/dev/null > "${COLLECTION_DIR}/packages/package_verification.txt" || \
                echo "# debsums not available or timed out" > "${COLLECTION_DIR}/packages/package_verification.txt"
            ;;
        rhel|centos|fedora|rocky|alma|oracle)
            safe_run "${COLLECTION_DIR}/packages/installed_packages.txt" "installed packages" rpm -qa --last
            # RPM verification
            log_info "Collecting: package verification (may take time)"
            timeout 120 rpm -Va 2>/dev/null > "${COLLECTION_DIR}/packages/package_verification.txt" || \
                echo "# rpm -Va timed out" > "${COLLECTION_DIR}/packages/package_verification.txt"
            ;;
        alpine)
            safe_run "${COLLECTION_DIR}/packages/installed_packages.txt" "installed packages" apk list -I
            ;;
        *)
            echo "# Unknown package manager" > "${COLLECTION_DIR}/packages/installed_packages.txt"
            ;;
    esac

    # ======================================================================
    # SUSPICIOUS FILES (Section 9)
    # ======================================================================
    log_info "=== SUSPICIOUS FILES ==="

    # Hidden files in /tmp and /var/tmp
    safe_run "${COLLECTION_DIR}/files/tmp_hidden.txt" "hidden files in /tmp" \
        find /tmp /var/tmp -name ".*" -type f 2>/dev/null

    # /dev/shm contents
    safe_run "${COLLECTION_DIR}/files/dev_shm.txt" "/dev/shm contents" \
        ls -la /dev/shm/

    # World-writable files in system directories
    safe_run "${COLLECTION_DIR}/files/world_writable.txt" "world-writable system files" \
        find /etc /usr /bin /sbin -type f -perm -002 2>/dev/null

    # SUID/SGID binaries in non-standard locations
    safe_run "${COLLECTION_DIR}/files/suid_nonstandard.txt" "SUID/SGID non-standard" \
        find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | grep -vE "^/(usr|bin|sbin|lib)"

    # Recently modified files in system directories (last 24 hours)
    safe_run "${COLLECTION_DIR}/files/recently_modified_system.txt" "recently modified system files" \
        find /etc /usr/bin /usr/sbin -type f -mtime -1 2>/dev/null

    # ======================================================================
    # METADATA & PACKAGING
    # ======================================================================
    log_info "=== FINALIZING ==="

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Create metadata file
    cat > "$METADATA_FILE" << EOF
{
    "hostname": "${HOSTNAME}",
    "fqdn": "$(hostname -f 2>/dev/null || echo $HOSTNAME)",
    "collection_time": "$(date -Iseconds)",
    "timestamp": "${TIMESTAMP}",
    "duration_seconds": ${duration},
    "os_family": "${os_family}",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "collector_version": "1.0.0",
    "salt_minion_id": "$(cat /etc/salt/minion_id 2>/dev/null || echo 'unknown')"
}
EOF

    # Create tarball
    log_info "Creating tarball: ${TARBALL}"
    cd "${OUTPUT_DIR}"
    tar -czf "${TARBALL}" "$(basename ${COLLECTION_DIR})"

    # Cleanup collection directory
    rm -rf "${COLLECTION_DIR}"

    # Set secure permissions
    chmod 600 "${TARBALL}"

    local tarball_size=$(stat -c%s "${TARBALL}" 2>/dev/null || echo "unknown")

    echo ""
    echo "========================================"
    echo "COLLECTION COMPLETE"
    echo "========================================"
    echo "Host: ${HOSTNAME}"
    echo "Duration: ${duration} seconds"
    echo "Output: ${TARBALL}"
    echo "Size: ${tarball_size} bytes"
    echo "========================================"

    # Output the tarball path for Salt to capture
    echo "TARBALL_PATH:${TARBALL}"
}

# Run main function
main "$@"
