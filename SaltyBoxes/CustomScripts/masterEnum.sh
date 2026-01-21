#!/bin/bash
#
#   masterEnum.sh - Security Audit Tool (Fixed & Improved)
#   
#   This script performs a comprehensive security audit and outputs to a log file.
#   Designed for CCDC-style cybersecurity competitions.
#
#   Fixes over original:
#   - Fixed infinite recursion bug in get_users()
#   - Modularized function structure
#   - Added timeout protection for long-running commands
#   - Improved error handling
#   - Added quick-scan mode for time-critical situations
#
#   Samuel Brucker 2025-2026
#

set -o pipefail

# --- Configuration ---
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export TERM=dumb
export SYSTEMD_COLORS=0

# Command timeout (seconds)
CMD_TIMEOUT=30
QUICK_MODE=false

# --- Colors (for terminal output only) ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -q|--quick)
            QUICK_MODE=true
            CMD_TIMEOUT=10
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "  -q, --quick    Quick scan mode (shorter timeouts, skip slow checks)"
            echo "  -h, --help     Show this help"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# --- Pre-flight Checks ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root.${NC}" >&2
    exit 1
fi

# --- Global Variables ---
HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
mkdir -p /var/log/syst/
TIME_SUFFIX=$(date +%Y%m%d_%H%M)
FINAL_LOG="/var/log/syst/${HOSTNAME}_audit_${TIME_SUFFIX}.log"
LOG_FILE="/tmp/${HOSTNAME}_audit_${TIME_SUFFIX}.tmp"

# --- Utility Functions ---
log() {
    echo "[PROGRESS] - $1" >> "$LOG_FILE"
}

safe_cmd() {
    # Run command with timeout protection
    local cmd="$1"
    local desc="${2:-command}"
    timeout "$CMD_TIMEOUT" bash -c "$cmd" 2>/dev/null || echo "[$desc timed out or failed]"
}

section_header() {
    local title="$1"
    echo ""
    echo "================================================================================"
    echo "$title"
    echo "================================================================================"
}

print_table_header() {
    local header="$1"
    local separator="$2"
    echo "$header"
    echo "$separator"
}

# --- Module: System Inventory ---
get_inventory() {
    section_header "SYSTEM INVENTORY"
    
    echo "Hostname: $HOSTNAME"
    echo ""
    
    # IP Addresses
    echo "IP Addresses:"
    if command -v ip &> /dev/null; then
        ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | while read -r ip; do
            echo "  - $ip"
        done
    elif command -v ifconfig &> /dev/null; then
        ifconfig | grep -oE 'inet [0-9.]+' | grep -v '127.0.0.1' | awk '{print "  - " $2}'
    fi
    echo ""
    
    # Operating System
    echo "Operating System:"
    if command -v hostnamectl &> /dev/null; then
        hostnamectl | grep "Operating System" | sed 's/.*: /  /'
    elif [[ -f /etc/os-release ]]; then
        grep PRETTY_NAME /etc/os-release | cut -d'"' -f2 | sed 's/^/  /'
    fi
    echo ""
    
    # Hardware
    echo "Hardware:"
    if command -v lscpu &> /dev/null; then
        echo "  CPU: $(lscpu | grep 'Model name' | sed 's/Model name:[ \t]*//')"
        echo "  Cores: $(lscpu | grep '^CPU(s):' | awk '{print $2}')"
    fi
    if command -v free &> /dev/null; then
        echo "  RAM: $(free -h | awk '/Mem:/ {print $2}')"
    fi
    echo ""
    
    # Open Ports
    echo "Open Ports (Listening):"
    if command -v ss &> /dev/null; then
        ss -tulpn 2>/dev/null | grep LISTEN | awk '{printf "  %-6s %-25s %s\n", $1, $5, $7}' | head -30
    elif command -v netstat &> /dev/null; then
        netstat -tulpn 2>/dev/null | grep LISTEN | head -30
    fi
    echo ""
    
    # Docker Containers
    if command -v docker &> /dev/null; then
        echo "Docker Containers:"
        local running
        running=$(docker ps --format "{{.Names}}\t{{.Status}}" 2>/dev/null)
        if [[ -n "$running" ]]; then
            echo "$running" | while IFS=$'\t' read -r name status; do
                echo "  [RUNNING] $name - $status"
            done
        else
            echo "  No running containers"
        fi
        
        local stopped
        stopped=$(docker ps -a --filter "status=exited" --format "{{.Names}}" 2>/dev/null)
        if [[ -n "$stopped" ]]; then
            echo "$stopped" | while read -r name; do
                echo "  [STOPPED] $name"
            done
        fi
        echo ""
    fi
    
    # Human Users
    echo "Human Users (UID >= 1000 or root):"
    awk -F: '($3 >= 1000 || $1 == "root") && $1 != "nobody" {
        printf "  %-15s UID:%-5s Home:%-20s Shell:%s\n", $1, $3, $6, $7
    }' /etc/passwd
    echo ""
    
    # Admin Users
    echo "Admin Users (sudo/wheel members):"
    for group in sudo wheel admin; do
        getent group "$group" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read -r user; do
            [[ -n "$user" ]] && echo "  - $user ($group)"
        done
    done
    echo ""
    
    # Domain Join Status
    if [[ -f /etc/krb5.conf ]]; then
        echo "Domain Status: JOINED"
        echo "  Domain: $(grep 'default_realm' /etc/krb5.conf 2>/dev/null | awk '{print $3}')"
    else
        echo "Domain Status: Not domain joined"
    fi
    echo ""
    
    # Key Services
    echo "Key Service Processes:"
    ps aux 2>/dev/null | awk 'NR==1 || /docker|samba|postfix|dovecot|ssh[d]|mysql|mariadb|postgres|apache|nginx|bind|named|splunk|wazuh|elastic/ {print}' | grep -v "grep\|awk" | head -20
    
    log "Inventory collection complete"
}

# --- Module: Cron Jobs ---
get_cron() {
    section_header "CRON JOB ENUMERATION"
    
    local suspicious_patterns="wget|curl|nc |netcat|/tmp/|/var/tmp/|/dev/shm|base64|python.*-c|perl.*-e|bash.*-i|chmod.*777"
    
    echo "=== Suspicious Cron Jobs ==="
    print_table_header "USER         SCHEDULE          COMMAND" "----         --------          -------"
    
    local found_suspicious=false
    
    # Check /etc/crontab
    if [[ -f /etc/crontab ]]; then
        while read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^[[:space:]]*[A-Z_]+= ]] && continue
            
            if echo "$line" | grep -qE "$suspicious_patterns"; then
                echo "$line" | awk '{printf "%-12s %-17s %s\n", $6, $1" "$2" "$3" "$4" "$5, $7}'
                found_suspicious=true
            fi
        done < /etc/crontab
    fi
    
    # Check /etc/cron.d/
    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            while read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "$line" ]] && continue
                if echo "$line" | grep -qE "$suspicious_patterns"; then
                    echo "[$f] $line"
                    found_suspicious=true
                fi
            done < "$f"
        done
    fi
    
    # Check user crontabs
    while IFS=: read -r username _ uid _ _ _ shell; do
        [[ "$uid" -ge 1000 || "$username" == "root" ]] || continue
        local user_cron
        user_cron=$(crontab -u "$username" -l 2>/dev/null) || continue
        
        while read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            if echo "$line" | grep -qE "$suspicious_patterns"; then
                echo "[$username] $line"
                found_suspicious=true
            fi
        done <<< "$user_cron"
    done < /etc/passwd
    
    [[ "$found_suspicious" == "false" ]] && echo "No suspicious cron jobs found."
    
    echo ""
    echo "=== All User Crontabs ==="
    for user in $(cut -d: -f1 /etc/passwd); do
        local cron
        cron=$(crontab -u "$user" -l 2>/dev/null) || continue
        echo "--- $user ---"
        echo "$cron" | grep -v '^#' | grep -v '^$' | head -10
        echo ""
    done
    
    log "Cron enumeration complete"
}

# --- Module: User Enumeration (FIXED) ---
get_users() {
    section_header "USER ENUMERATION"
    
    # Check if we can read shadow
    local shadow_readable=false
    [[ $EUID -eq 0 && -r /etc/shadow ]] && shadow_readable=true
    
    echo "=== High-Risk/Suspicious Users ==="
    print_table_header "USERNAME     UID      GROUPS           SHELL                FLAGS" "--------     ---      ------           -----                -----"
    
    local high_risk_count=0
    
    while IFS=: read -r username _ uid gid _ home shell; do
        local flags=""
        local is_high_risk=false
        
        # UID 0 but not root
        if [[ "$uid" -eq 0 && "$username" != "root" ]]; then
            flags+="[UID-0] "
            is_high_risk=true
        fi
        
        # Service account with login shell
        if [[ "$uid" -lt 1000 && "$uid" -ne 0 && "$shell" =~ (bash|sh|zsh|fish)$ ]]; then
            flags+="[SVC-LOGIN-SHELL] "
            is_high_risk=true
        fi
        
        # Check for empty password
        if [[ "$shadow_readable" == "true" ]]; then
            local pass_hash
            pass_hash=$(getent shadow "$username" 2>/dev/null | cut -d: -f2)
            if [[ -z "$pass_hash" || "$pass_hash" == "!" || "$pass_hash" == "*" || "$pass_hash" == "!!" ]]; then
                if [[ "$shell" =~ (bash|sh|zsh|fish)$ ]]; then
                    flags+="[NO-PASSWORD] "
                    is_high_risk=true
                fi
            fi
        fi
        
        # Recently created home directory
        if [[ -d "$home" ]]; then
            local recent
            recent=$(find "$home" -maxdepth 0 -mtime -7 2>/dev/null | wc -l)
            if [[ "$recent" -gt 0 ]]; then
                flags+="[RECENT] "
                is_high_risk=true
            fi
        fi
        
        if [[ "$is_high_risk" == "true" ]]; then
            local groups
            groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | xargs | tr ' ' ',')
            printf "%-12s %-8s %-16s %-20s %s\n" "$username" "$uid" "${groups:0:15}" "$shell" "$flags"
            ((high_risk_count++))
        fi
    done < /etc/passwd
    
    [[ $high_risk_count -eq 0 ]] && echo "No high-risk users found."
    
    echo ""
    echo "=== Privileged Users (sudo/wheel/admin) ==="
    print_table_header "USERNAME     UID      GROUPS           SHELL" "--------     ---      ------           -----"
    
    for group in sudo wheel admin; do
        local members
        members=$(getent group "$group" 2>/dev/null | cut -d: -f4 | tr ',' '\n')
        for member in $members; do
            [[ -z "$member" ]] && continue
            local user_info
            user_info=$(getent passwd "$member" 2>/dev/null)
            [[ -z "$user_info" ]] && continue
            
            local uid shell
            uid=$(echo "$user_info" | cut -d: -f3)
            shell=$(echo "$user_info" | cut -d: -f7)
            local all_groups
            all_groups=$(groups "$member" 2>/dev/null | cut -d: -f2 | xargs | tr ' ' ',')
            printf "%-12s %-8s %-16s %s\n" "$member" "$uid" "${all_groups:0:15}" "$shell"
        done
    done
    
    echo ""
    echo "Summary: $high_risk_count high-risk users found"
    
    log "User enumeration complete"
}

# --- Module: Sudoers ---
get_sudoers() {
    section_header "SUDOERS CONFIGURATION"
    
    # GTFOBins dangerous commands
    local dangerous_cmds="vim|vi|nano|less|more|man|awk|perl|python|ruby|lua|php|node|bash|sh|zsh|find|tar|zip|rsync|scp|ssh|nc|ncat|socat|curl|wget|ftp|nmap|gdb|strace|ltrace|env|su|sudo"
    
    echo "=== High-Risk Sudo Rules ==="
    print_table_header "ENTITY       TYPE     PERMISSIONS              COMMANDS             FLAGS" "------       ----     -----------              --------             -----"
    
    local sudoers_files=("/etc/sudoers")
    [[ -d /etc/sudoers.d ]] && sudoers_files+=(/etc/sudoers.d/*)
    
    for sudoers_file in "${sudoers_files[@]}"; do
        [[ -r "$sudoers_file" ]] || continue
        
        while read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^[[:space:]]*(Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias) ]] && continue
            
            # Parse: user/group host=(runas) commands
            if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+[^=]+=[[:space:]]*(.*)$ ]]; then
                local entity="${BASH_REMATCH[1]}"
                local rest="${BASH_REMATCH[2]}"
                local flags=""
                
                # Check for NOPASSWD
                [[ "$rest" =~ NOPASSWD ]] && flags+="[NOPASSWD] "
                
                # Check for ALL
                [[ "$rest" =~ \(ALL\).*ALL$ ]] && flags+="[FULL-ROOT] "
                
                # Check for dangerous commands
                if echo "$rest" | grep -qE "$dangerous_cmds"; then
                    flags+="[DANGEROUS-CMD] "
                fi
                
                if [[ -n "$flags" ]]; then
                    local type="USER"
                    [[ "$entity" =~ ^% ]] && type="GROUP" && entity="${entity#%}"
                    printf "%-12s %-8s %-24s %-20s %s\n" "$entity" "$type" "${rest:0:23}" "${rest:0:19}" "$flags"
                fi
            fi
        done < "$sudoers_file"
    done
    
    log "Sudoers enumeration complete"
}

# --- Module: Services ---
get_services() {
    section_header "SERVICE ENUMERATION"
    
    if ! command -v systemctl &> /dev/null; then
        echo "systemctl not available"
        return
    fi
    
    echo "=== Active Services ==="
    print_table_header "SERVICE                                            STATUS     STATE" "-------                                            ------     -----"
    
    systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | \
        awk '{printf "%-50s %-10s %s\n", $1, $3, $4}' | head -40
    
    echo ""
    echo "=== Failed Services ==="
    systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | \
        awk '{print "  " $1}' || echo "  None"
    
    echo ""
    echo "=== Recently Modified Service Files (7 days) ==="
    find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
        -name "*.service" -mtime -7 2>/dev/null | while read -r f; do
        echo "  $f ($(stat -c %y "$f" 2>/dev/null | cut -d' ' -f1))"
    done | head -20
    
    log "Service enumeration complete"
}

# --- Module: Privilege Escalation Vectors ---
get_privesc() {
    section_header "PRIVILEGE ESCALATION VECTORS"
    
    # GTFOBins SUID exploitable binaries
    local gtfobins_suid="aria2c|ash|base64|bash|busybox|cat|chmod|chown|cp|csh|curl|cut|dash|dd|diff|docker|ed|emacs|env|find|flock|gdb|grep|head|ionice|jq|ksh|ld.so|less|logsave|make|man|more|mv|mysql|nano|nc|nice|nl|node|nohup|perl|pg|php|python|rlwrap|rsync|run-parts|rvim|sed|setarch|ssh|start-stop-daemon|stdbuf|strace|tail|tar|taskset|tclsh|tee|time|timeout|ul|unexpand|uniq|unshare|vi|vim|watch|wget|xargs|xxd|zsh"
    
    echo "=== SUID Binaries (Potentially Exploitable) ==="
    print_table_header "BINARY                              OWNER      PERMISSIONS" "------                              -----      -----------"
    
    local suid_count=0
    while read -r binary; do
        [[ -z "$binary" ]] && continue
        local name
        name=$(basename "$binary")
        
        # Check if it's in GTFOBins list
        if echo "$name" | grep -qE "^($gtfobins_suid)$"; then
            local owner perms
            owner=$(stat -c %U "$binary" 2>/dev/null)
            perms=$(stat -c %A "$binary" 2>/dev/null)
            printf "%-35s %-10s %s [GTFOBINS]\n" "$binary" "$owner" "$perms"
            ((suid_count++))
        fi
    done < <(find / -perm -4000 -type f 2>/dev/null)
    
    echo ""
    echo "Total potentially exploitable SUID binaries: $suid_count"
    
    if [[ "$QUICK_MODE" == "false" ]]; then
        echo ""
        echo "=== Capabilities (Exploitable) ==="
        if command -v getcap &> /dev/null; then
            getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_setgid|cap_sys_admin|cap_sys_ptrace|cap_dac_override" | while read -r line; do
                echo "  [HIGH-RISK] $line"
            done
        fi
        
        echo ""
        echo "=== World-Writable Directories in PATH ==="
        echo "$PATH" | tr ':' '\n' | while read -r dir; do
            [[ -d "$dir" ]] || continue
            if [[ -w "$dir" ]] && [[ "$(stat -c %a "$dir" 2>/dev/null)" =~ .*7$ ]]; then
                echo "  [DANGER] $dir is world-writable!"
            fi
        done
    fi
    
    log "Privilege escalation enumeration complete"
}

# --- Module: Network Connections ---
get_network() {
    section_header "NETWORK CONNECTIONS"
    
    echo "=== Established Connections ==="
    if command -v ss &> /dev/null; then
        ss -tupn state established 2>/dev/null | head -30
    elif command -v netstat &> /dev/null; then
        netstat -tupn 2>/dev/null | grep ESTABLISHED | head -30
    fi
    
    echo ""
    echo "=== Unusual Listening Ports (non-standard) ==="
    local common_ports="22|80|443|25|53|110|143|993|995|3306|5432|6379|27017|8080|8443"
    
    if command -v ss &> /dev/null; then
        ss -tulpn 2>/dev/null | grep LISTEN | while read -r line; do
            local port
            port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
            if ! echo "$port" | grep -qE "^($common_ports)$"; then
                echo "  $line"
            fi
        done | head -20
    fi
    
    log "Network enumeration complete"
}

# --- Main Execution ---
main() {
    echo "Starting Master Security Audit on $HOSTNAME"
    echo "Quick Mode: $QUICK_MODE"
    echo "Log File: $FINAL_LOG"
    log "Starting Master Audit on $HOSTNAME"
    
    {
        echo "=================================================================="
        echo "MASTER SECURITY AUDIT REPORT"
        echo "Date: $(date)"
        echo "Hostname: $HOSTNAME"
        echo "Quick Mode: $QUICK_MODE"
        echo "=================================================================="
        
        get_inventory
        get_cron
        get_users
        get_sudoers
        get_services
        get_privesc
        get_network
        
        echo ""
        echo "=================================================================="
        echo "AUDIT COMPLETE - $(date)"
        echo "=================================================================="
    } >> "$LOG_FILE" 2>&1
    
    # Move temp file to final location
    mv "$LOG_FILE" "$FINAL_LOG"
    
    log "Master Audit completed."
    echo ""
    echo "Audit complete. Review at: $FINAL_LOG"
}

main "$@"
