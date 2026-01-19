#!/bin/bash
#
# persistenceHunter.sh - Find Common Persistence Mechanisms
#
# This script hunts for common persistence techniques used by attackers.
# Essential for CCDC competitions to find red team backdoors.
#
# Checks:
# - Cron jobs (all locations)
# - Systemd services and timers
# - init.d scripts
# - Shell profiles/rc files
# - Authorized SSH keys
# - SUID/SGID binaries
# - LD_PRELOAD hooks
# - PAM backdoors
# - Hidden files and directories
# - Modified system binaries
# - Network persistence (reverse shells)
# - Kernel modules
#
# Usage: sudo ./persistenceHunter.sh [--fix] [--json]
#
# Samuel Brucker 2025-2026
#

set -o pipefail

# --- Configuration ---
FIX_MODE=false
JSON_OUTPUT=false
REPORT_FILE="/var/log/persistence_hunt_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Suspicious patterns
SUSPICIOUS_CMDS='wget|curl|nc |ncat|netcat|bash -i|sh -i|python.*-c|perl.*-e|ruby.*-e|/dev/tcp|/dev/udp|base64.*-d|openssl.*enc|socat|telnet|mkfifo|mknod'
SUSPICIOUS_PATHS='/tmp/|/var/tmp/|/dev/shm/|/dev/null.*&|\.hidden|/home/\.'
SUSPICIOUS_USERS='daemon|bin|sys|games|nobody'

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix)
            FIX_MODE=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--fix] [--json]"
            echo "  --fix   Attempt to remove found persistence (interactive)"
            echo "  --json  Output results as JSON"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# --- Helper Functions ---
declare -a FINDINGS

finding() {
    local severity="$1"
    local category="$2"
    local description="$3"
    local location="$4"
    local details="${5:-}"
    
    FINDINGS+=("$severity|$category|$description|$location|$details")
    
    case "$severity" in
        CRITICAL)
            echo -e "${RED}[CRITICAL]${NC} $category: $description"
            ;;
        HIGH)
            echo -e "${YELLOW}[HIGH]${NC} $category: $description"
            ;;
        MEDIUM)
            echo -e "${CYAN}[MEDIUM]${NC} $category: $description"
            ;;
        *)
            echo -e "[INFO] $category: $description"
            ;;
    esac
    echo "  Location: $location"
    [[ -n "$details" ]] && echo "  Details: $details"
    echo ""
    
    # Log to file
    echo "[$severity] $category: $description" >> "$REPORT_FILE"
    echo "  Location: $location" >> "$REPORT_FILE"
    [[ -n "$details" ]] && echo "  Details: $details" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

section() {
    echo ""
    echo -e "${GREEN}=== $1 ===${NC}"
    echo "=== $1 ===" >> "$REPORT_FILE"
}

# --- Start Hunt ---
echo "=============================================="
echo "     PERSISTENCE HUNTER - CCDC Edition       "
echo "=============================================="
echo "Report: $REPORT_FILE"
echo ""

# Record system baseline
{
    echo "Persistence Hunt Report"
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "======================================"
    echo ""
} > "$REPORT_FILE"

# --- 1. Cron Jobs ---
section "Hunting in Cron Jobs"

# System crontab
if [[ -f /etc/crontab ]]; then
    while read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*[A-Z_]+=.* ]] && continue
        
        if echo "$line" | grep -qE "$SUSPICIOUS_CMDS|$SUSPICIOUS_PATHS"; then
            finding "CRITICAL" "CRON" "Suspicious command in /etc/crontab" "/etc/crontab" "$line"
        fi
    done < /etc/crontab
fi

# /etc/cron.d/
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    while read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        if echo "$line" | grep -qE "$SUSPICIOUS_CMDS|$SUSPICIOUS_PATHS"; then
            finding "CRITICAL" "CRON" "Suspicious cron.d entry" "$f" "$line"
        fi
    done < "$f"
done

# cron directories
for dir in /etc/cron.{hourly,daily,weekly,monthly}; do
    [[ -d "$dir" ]] || continue
    for script in "$dir"/*; do
        [[ -f "$script" ]] || continue
        
        # Check if script is suspicious
        if grep -lE "$SUSPICIOUS_CMDS" "$script" 2>/dev/null; then
            finding "HIGH" "CRON" "Suspicious script in cron directory" "$script" "Contains suspicious commands"
        fi
        
        # Check for non-standard scripts
        local script_name
        script_name=$(basename "$script")
        if [[ "$script_name" =~ \.(sh|py|pl|rb)$ ]] && [[ ! -x "$script" ]]; then
            finding "MEDIUM" "CRON" "Non-executable script in cron directory" "$script" "May be benign"
        fi
    done
done

# User crontabs
for user in $(cut -d: -f1 /etc/passwd); do
    local cron
    cron=$(crontab -u "$user" -l 2>/dev/null) || continue
    
    while read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        
        if echo "$line" | grep -qE "$SUSPICIOUS_CMDS|$SUSPICIOUS_PATHS"; then
            finding "CRITICAL" "CRON" "Suspicious user cron entry" "crontab -u $user -l" "$line"
        fi
    done <<< "$cron"
done

# /var/spool/cron/
find /var/spool/cron* -type f 2>/dev/null | while read -r f; do
    if grep -lE "$SUSPICIOUS_CMDS|$SUSPICIOUS_PATHS" "$f" 2>/dev/null; then
        finding "CRITICAL" "CRON" "Suspicious entry in spool cron" "$f" "Contains suspicious patterns"
    fi
done

# --- 2. Systemd Services ---
section "Hunting in Systemd Services"

# Non-standard service files in writable locations
for dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
    [[ -d "$dir" ]] || continue
    
    find "$dir" -name "*.service" -mtime -30 2>/dev/null | while read -r svc; do
        # Recently modified
        finding "MEDIUM" "SYSTEMD" "Recently modified service file" "$svc" "Modified in last 30 days"
        
        # Check for suspicious commands
        if grep -qE "$SUSPICIOUS_CMDS" "$svc" 2>/dev/null; then
            finding "CRITICAL" "SYSTEMD" "Suspicious command in service" "$svc" "$(grep -E 'ExecStart|ExecStop' "$svc")"
        fi
    done
    
    # Check for services running from /tmp or user directories
    find "$dir" -name "*.service" 2>/dev/null | while read -r svc; do
        if grep -qE "ExecStart.*/tmp/|ExecStart.*/home/" "$svc" 2>/dev/null; then
            finding "CRITICAL" "SYSTEMD" "Service executing from suspicious path" "$svc" "$(grep ExecStart "$svc")"
        fi
    done
done

# Systemd timers
systemctl list-timers --all --no-pager 2>/dev/null | grep -v "^NEXT" | while read -r line; do
    local timer_name
    timer_name=$(echo "$line" | awk '{print $NF}')
    [[ -z "$timer_name" ]] && continue
    
    local timer_file
    timer_file=$(systemctl show "$timer_name" --property=FragmentPath 2>/dev/null | cut -d= -f2)
    
    if [[ -f "$timer_file" ]] && [[ $(stat -c %Y "$timer_file" 2>/dev/null) -gt $(date -d "30 days ago" +%s) ]]; then
        finding "MEDIUM" "SYSTEMD" "Recently created/modified timer" "$timer_file" "$timer_name"
    fi
done

# --- 3. init.d Scripts ---
section "Hunting in init.d Scripts"

find /etc/init.d /etc/rc*.d -type f 2>/dev/null | while read -r script; do
    if grep -qE "$SUSPICIOUS_CMDS" "$script" 2>/dev/null; then
        finding "HIGH" "INITD" "Suspicious init script" "$script" "Contains suspicious commands"
    fi
done

# --- 4. Shell Profiles ---
section "Hunting in Shell Profiles"

PROFILE_FILES=(
    "/etc/profile"
    "/etc/profile.d/*"
    "/etc/bash.bashrc"
    "/etc/bashrc"
    "/etc/zsh/zshrc"
)

for f in "${PROFILE_FILES[@]}"; do
    for file in $f; do
        [[ -f "$file" ]] || continue
        
        if grep -qE "$SUSPICIOUS_CMDS" "$file" 2>/dev/null; then
            finding "CRITICAL" "SHELL" "Suspicious command in global profile" "$file" "$(grep -E "$SUSPICIOUS_CMDS" "$file" | head -1)"
        fi
    done
done

# User profiles
for home in /home/* /root; do
    [[ -d "$home" ]] || continue
    
    for rc in "$home"/.bashrc "$home"/.bash_profile "$home"/.profile "$home"/.zshrc; do
        [[ -f "$rc" ]] || continue
        
        if grep -qE "$SUSPICIOUS_CMDS" "$rc" 2>/dev/null; then
            finding "CRITICAL" "SHELL" "Suspicious command in user profile" "$rc" "$(grep -E "$SUSPICIOUS_CMDS" "$rc" | head -1)"
        fi
    done
done

# --- 5. SSH Authorized Keys ---
section "Hunting in SSH Keys"

find /home /root -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
    local count
    count=$(wc -l < "$keyfile")
    
    # Report all keys
    finding "MEDIUM" "SSH" "Authorized keys file found" "$keyfile" "$count keys present"
    
    # Check for unusual key types or comments
    while read -r key; do
        [[ -z "$key" ]] && continue
        [[ "$key" =~ ^# ]] && continue
        
        # Check for command= restrictions (could be malicious)
        if echo "$key" | grep -q "command="; then
            finding "HIGH" "SSH" "Key with forced command" "$keyfile" "$(echo "$key" | cut -c1-100)"
        fi
        
        # Check for unusual key types
        if ! echo "$key" | grep -qE "^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss)"; then
            finding "MEDIUM" "SSH" "Unusual key format" "$keyfile" "$(echo "$key" | cut -c1-50)"
        fi
    done < "$keyfile"
done

# --- 6. SUID/SGID Binaries ---
section "Hunting for Unusual SUID/SGID"

# Known exploitable binaries (GTFOBins)
EXPLOITABLE="nmap|vim|vi|nano|less|more|man|awk|perl|python|ruby|lua|php|node|bash|sh|zsh|find|tar|zip|rsync|nc|gdb|strace|ltrace|env|docker|kubectl"

find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r binary; do
    local name
    name=$(basename "$binary")
    
    # Check against exploitable list
    if echo "$name" | grep -qE "^($EXPLOITABLE)$"; then
        finding "HIGH" "SUID" "Potentially exploitable SUID binary" "$binary" "$(ls -la "$binary")"
    fi
    
    # Check for SUID in unusual locations
    if [[ "$binary" =~ ^/tmp/ ]] || [[ "$binary" =~ ^/home/ ]] || [[ "$binary" =~ ^/var/tmp/ ]]; then
        finding "CRITICAL" "SUID" "SUID binary in suspicious location" "$binary" "$(ls -la "$binary")"
    fi
    
    # Check for recently modified SUID
    if [[ $(find "$binary" -mtime -7 2>/dev/null | wc -l) -gt 0 ]]; then
        finding "HIGH" "SUID" "Recently modified SUID binary" "$binary" "Modified in last 7 days"
    fi
done

# --- 7. LD_PRELOAD Hooks ---
section "Hunting for LD_PRELOAD Hooks"

# Check /etc/ld.so.preload
if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
    finding "CRITICAL" "LDPRELOAD" "ld.so.preload is not empty" "/etc/ld.so.preload" "$(cat /etc/ld.so.preload)"
fi

# Check environment files for LD_PRELOAD
grep -r "LD_PRELOAD" /etc/profile* /etc/bash* /etc/environment 2>/dev/null | while read -r line; do
    finding "CRITICAL" "LDPRELOAD" "LD_PRELOAD set in environment" "$(echo "$line" | cut -d: -f1)" "$line"
done

# --- 8. PAM Configuration ---
section "Hunting in PAM Configuration"

# Check for unusual PAM modules
find /etc/pam.d -type f 2>/dev/null | while read -r pamfile; do
    # Check for suspicious auth modules
    if grep -qE "pam_exec|pam_script" "$pamfile" 2>/dev/null; then
        finding "HIGH" "PAM" "Potentially dangerous PAM module" "$pamfile" "$(grep -E 'pam_exec|pam_script' "$pamfile")"
    fi
done

# Check for modified PAM modules
find /lib/*/security /lib/security -name "pam_*.so" -mtime -30 2>/dev/null | while read -r module; do
    finding "HIGH" "PAM" "Recently modified PAM module" "$module" "Modified in last 30 days"
done

# --- 9. Hidden Files ---
section "Hunting for Hidden Files"

# Hidden executables in common locations
find /home /tmp /var/tmp /opt -name ".*" -type f -executable 2>/dev/null | head -50 | while read -r f; do
    finding "MEDIUM" "HIDDEN" "Hidden executable file" "$f" "$(file "$f")"
done

# Hidden directories in unusual places
find / -maxdepth 3 -type d -name ".*" ! -name "." ! -name ".." 2>/dev/null | grep -vE "^/home/|^/root/|/\.git$|/\.cache$|/\.local$|/\.config$" | while read -r d; do
    finding "MEDIUM" "HIDDEN" "Hidden directory in unusual location" "$d"
done

# --- 10. Network Persistence ---
section "Hunting for Network Backdoors"

# Check for listeners on unusual ports
ss -tulpn 2>/dev/null | grep LISTEN | while read -r line; do
    local port
    port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
    local process
    process=$(echo "$line" | awk '{print $7}')
    
    # Check for high ports with no clear association
    if [[ "$port" -gt 1024 ]] && [[ "$port" -lt 65535 ]]; then
        if echo "$process" | grep -qE "sh|bash|python|perl|nc|ncat"; then
            finding "CRITICAL" "NETWORK" "Suspicious listening process" "Port $port" "$line"
        fi
    fi
done

# Check for reverse shell processes
ps aux 2>/dev/null | grep -E "bash.*-i|nc.*-e|python.*socket|perl.*socket" | grep -v grep | while read -r line; do
    finding "CRITICAL" "NETWORK" "Potential reverse shell process" "Running process" "$line"
done

# --- 11. Kernel Modules ---
section "Hunting for Suspicious Kernel Modules"

# Check for recently loaded modules
find /lib/modules -name "*.ko" -mtime -30 2>/dev/null | while read -r module; do
    finding "HIGH" "KERNEL" "Recently modified kernel module" "$module"
done

# Check for unsigned/unusual modules
lsmod 2>/dev/null | tail -n +2 | while read -r line; do
    local module
    module=$(echo "$line" | awk '{print $1}')
    
    # Check if module info is available
    if ! modinfo "$module" &>/dev/null; then
        finding "HIGH" "KERNEL" "Kernel module with no modinfo" "$module" "Could be rootkit"
    fi
done

# --- 12. Modified System Binaries ---
section "Checking System Binary Integrity"

if command -v rpm &>/dev/null; then
    rpm -Va 2>/dev/null | grep -E "^..5" | head -20 | while read -r line; do
        finding "HIGH" "INTEGRITY" "Modified system file (RPM)" "$(echo "$line" | awk '{print $NF}')" "$line"
    done
elif command -v dpkg &>/dev/null; then
    dpkg --verify 2>/dev/null | grep -v "^??" | head -20 | while read -r line; do
        finding "HIGH" "INTEGRITY" "Modified system file (DPKG)" "$(echo "$line" | awk '{print $NF}')" "$line"
    done
fi

# --- Summary ---
echo ""
echo "=============================================="
echo "              HUNT COMPLETE                  "
echo "=============================================="
echo ""
echo "Total findings: ${#FINDINGS[@]}"
echo "Report saved to: $REPORT_FILE"
echo ""

# Count by severity
critical=$(printf '%s\n' "${FINDINGS[@]}" | grep -c "^CRITICAL" || true)
high=$(printf '%s\n' "${FINDINGS[@]}" | grep -c "^HIGH" || true)
medium=$(printf '%s\n' "${FINDINGS[@]}" | grep -c "^MEDIUM" || true)

echo -e "  ${RED}CRITICAL: $critical${NC}"
echo -e "  ${YELLOW}HIGH: $high${NC}"
echo -e "  ${CYAN}MEDIUM: $medium${NC}"
echo ""

if [[ "$FIX_MODE" == "true" ]] && [[ $critical -gt 0 || $high -gt 0 ]]; then
    echo "Fix mode enabled but not fully implemented."
    echo "Review findings manually and take appropriate action."
fi

# JSON output
if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo ""
    echo "JSON output:"
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"findings\": ["
    
    first=true
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev cat desc loc det <<< "$f"
        [[ "$first" == "true" ]] || echo ","
        echo "    {\"severity\": \"$sev\", \"category\": \"$cat\", \"description\": \"$desc\", \"location\": \"$loc\"}"
        first=false
    done
    
    echo "  ]"
    echo "}"
fi
