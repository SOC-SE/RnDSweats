#!/bin/bash

set -euo pipefail

# ==============================================================================
# File: System_Enumerator.sh
# Description: Performs advanced enumeration on a Linux machine.
#              Prompts the user to select categories of information to gather, such as system overview, users, network, processes, logs, etc.
#              Gathers verbose details for injects, incident reporting, and threat hunting. Checks for key indicators like suspicious processes,
#              open ports, cron jobs, installed packages, and potential security issues. Outputs to console and optionally saves to a report file.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS (dnf).
#              Designed to align with Perfect Box Framework (PBF) elements like System Pruning, Log Aggregation, IDS, and threat hunting.
#
# Dependencies: Standard Linux tools (e.g., ps, netstat/ss, awk, grep). Optional: chkrootkit or rkhunter for rootkit detection (prompts if not installed).
# Usage: sudo ./System_Enumerator.sh
#        Follow on-screen prompts to select enumeration categories.
# Notes: 
# - Run as root for full access (e.g., to /etc/shadow, raw sockets).
# - Use this to baseline systems, detect red team artifacts, and generate reports.
# - Outputs are timestamped and can be exported to /root/enum_report.txt for easy sharing.
# - For threat hunting: Looks for common persistence mechanisms (e.g., cron, unusual users, listening ports).
# ==============================================================================

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
 _____                             ____  _     
| ____|_ __  _   _ _ __ ___       |  _ \| |____
|  _| | '_ \| | | | '_ ` _ \ _____| |_) | |_  /
| |___| | | | |_| | | | | | |_____|  __/| |/ / 
|_____|_| |_|\__,_|_| |_| |_|     |_|   |_/___| 
EOF
echo -e "\033[0m"
echo "System Enumerator"
echo "---------------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
REPORT_FILE="/root/enum_report.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

append_to_report() {
    echo "$1" >> "$REPORT_FILE"
}

# New helper for counting outputs
count_and_log() {
    local cmd="$1"
    local desc="$2"
    local output=""
    local status=0

    set +e
    output=$(eval "$cmd" 2>/dev/null)
    status=$?
    set -e

    local count=0
    if [ -n "$output" ]; then
        count=$(printf '%s\n' "$output" | wc -l)
    fi

    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}No $desc found.${NC}"
        append_to_report "No $desc found."
    else
        echo -e "${GREEN}Found $count $desc.${NC}"
    append_to_report "Found $count $desc."
    printf '%s\n' "$output" | tee -a "$REPORT_FILE"
    fi

    if [ "$status" -ne 0 ]; then
        log_warn "$desc command reported errors; review output for details."
    fi
}

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root for full enumeration."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        QUERY_CMD="dpkg -l"
        UPDATE_CMD="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        QUERY_CMD="rpm -qa"
        UPDATE_CMD="dnf check-update"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        QUERY_CMD="rpm -qa"
        UPDATE_CMD="yum check-update"
    else
        log_warn "Unsupported package manager. Some features may be limited."
        PKG_MANAGER="unknown"
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Enumeration Functions ---

# 1. System Overview
enum_system_overview() {
    log_info "Gathering System Overview..."
    append_to_report "=== System Overview ($TIMESTAMP) ==="
    uname -a | tee -a "$REPORT_FILE"
    if command -v hostnamectl &> /dev/null; then hostnamectl | tee -a "$REPORT_FILE"; fi
    # Use /etc/os-release for portable distribution information
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "OS: ${PRETTY_NAME:-$NAME ${VERSION:-}}" | tee -a "$REPORT_FILE"
    elif [ -r /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "OS: ${DISTRIB_DESCRIPTION:-$DISTRIB_ID $DISTRIB_RELEASE}" | tee -a "$REPORT_FILE"
    elif [ -r /etc/redhat-release ]; then
        cat /etc/redhat-release | tee -a "$REPORT_FILE"
    else
        echo "OS: Unknown (no /etc/os-release or equivalents)" | tee -a "$REPORT_FILE"
    fi
    uptime | tee -a "$REPORT_FILE"
    df -h | tee -a "$REPORT_FILE"
    free -h | tee -a "$REPORT_FILE"
    log_info "System overview complete."
}

# 2. Users and Authentication
enum_users_auth() {
    log_info "Gathering Users and Authentication Info..."
    append_to_report "=== Users and Authentication ($TIMESTAMP) ==="
    cat /etc/passwd | tee -a "$REPORT_FILE"
    cat /etc/group | tee -a "$REPORT_FILE"
    if [ -r /etc/shadow ]; then awk -F: '{print $1 " has password? " ($2 != "" ? "Yes" : "No")}' /etc/shadow | tee -a "$REPORT_FILE"; fi
    if ! sudo -l 2>&1 | tee -a "$REPORT_FILE"; then
        log_warn "sudo -l failed (may require password, tty, or sudoers entry)."
    fi
    lastlog 2>/dev/null | head -20 | tee -a "$REPORT_FILE" || awk '/lastlog/ {print}' /var/log/auth.log 2>/dev/null | tee -a "$REPORT_FILE" || echo "lastlog not available" | tee -a "$REPORT_FILE"
    log_info "Users and auth info complete."
}

# 3. Network Information
enum_network() {
    log_info "Gathering Network Information..."
    append_to_report "=== Network Information ($TIMESTAMP) ==="
    ip addr show | tee -a "$REPORT_FILE"
    ip route | tee -a "$REPORT_FILE"
    if command -v ss &> /dev/null; then ss -tuln | tee -a "$REPORT_FILE"; else netstat -tuln 2>/dev/null | tee -a "$REPORT_FILE" || echo "netstat not available" | tee -a "$REPORT_FILE"; fi
    arp -a | tee -a "$REPORT_FILE"
    if command -v iptables &> /dev/null; then iptables -L -n -v | tee -a "$REPORT_FILE"; fi
    if command -v ufw &> /dev/null; then
        if ! ufw status verbose 2>&1 | tee -a "$REPORT_FILE"; then
            log_warn "ufw status command returned an error."
        fi
    fi
    if command -v firewall-cmd &> /dev/null; then
        if ! firewall-cmd --list-all 2>&1 | tee -a "$REPORT_FILE"; then
            log_warn "firewall-cmd --list-all returned an error (firewalld may be inactive)."
        fi
    fi
    log_info "Network info complete."
}

# 4. Processes and Services
enum_processes_services() {
    log_info "Gathering Processes and Services..."
    append_to_report "=== Processes and Services ($TIMESTAMP) ==="
    ps auxf | tee -a "$REPORT_FILE"
    if command -v systemctl &> /dev/null; then
        if ! systemctl list-units --type=service | tee -a "$REPORT_FILE"; then
            log_warn "systemctl list-units returned an error (systemd may be unavailable)."
        fi
    fi
    lsmod | tee -a "$REPORT_FILE"
    log_info "Processes and services complete."
}

# 5. Logs and Monitoring
enum_logs() {
    log_info "Gathering Logs and Monitoring Info..."
    append_to_report "=== Logs and Monitoring ($TIMESTAMP) ==="
    if command -v journalctl &> /dev/null; then
        if ! journalctl -n 50 | tee -a "$REPORT_FILE"; then
            log_warn "journalctl -n 50 returned an error."
        fi
    fi
    tail -n 50 /var/log/auth.log 2>/dev/null | tee -a "$REPORT_FILE" || tail -n 50 /var/log/secure 2>/dev/null | tee -a "$REPORT_FILE" || echo "No auth log available" | tee -a "$REPORT_FILE"
    tail -n 50 /var/log/syslog 2>/dev/null | tee -a "$REPORT_FILE" || tail -n 50 /var/log/messages 2>/dev/null | tee -a "$REPORT_FILE" || echo "No syslog available" | tee -a "$REPORT_FILE"
    log_info "Logs info complete."
}

# 6. File System and Integrity
enum_filesystem() {
    log_info "Gathering File System and Integrity Info..."
    append_to_report "=== File System and Integrity ($TIMESTAMP) ==="
    
    # SUID files: Targeted paths for speed (common escalation vectors)
    local suid_cmd="find /bin /usr/bin /usr/local/bin /sbin /usr/sbin /etc -perm -4000 -type f"
    count_and_log "$suid_cmd" "SUID files"
    
    # Hidden files in home
    local hidden_cmd="find /home -type f -name '.*'"
    count_and_log "$hidden_cmd" "hidden files in /home"
    
    # Disk usage (suppress errors for missing dirs, e.g., no /home on servers)
    du -sh /var /home /etc 2>/dev/null | tee -a "$REPORT_FILE" || echo "Disk usage check incomplete (some paths unavailable)." | tee -a "$REPORT_FILE"
    log_info "Disk usage summary added."
    
    if command -v aide &> /dev/null; then 
        log_info "Running AIDE integrity check..."
        if ! aide --check 2>&1 | tee -a "$REPORT_FILE"; then
            log_warn "AIDE integrity check returned a non-zero status; review the output above."
        fi
    else 
        log_warn "AIDE not installed for File Integrity Monitoring (FIM). Consider installing for baseline comparisons: apt install aide (Debian) or dnf/yum install aide (Fedora/CentOS)."
    fi
    log_info "File system info complete."
}

# 7. Security Tools and Configurations
enum_security() {
    log_info "Gathering Security Tools and Configurations..."
    append_to_report "=== Security Tools and Configurations ($TIMESTAMP) ==="
    
    # Cron jobs: Handle empty explicitly
    echo "Current user's crontab:" | tee -a "$REPORT_FILE"
    if crontab -l 2>/dev/null | grep -q .; then
        crontab -l 2>&1 | tee -a "$REPORT_FILE"
    else
        echo "no crontab for $(whoami)" | tee -a "$REPORT_FILE"
        log_info "No user crontab found (normal if none scheduled)."
    fi
    
    # System cron dirs (handle missing matches safely)
    echo "System cron entries:" | tee -a "$REPORT_FILE"
    if compgen -G "/etc/cron*" > /dev/null; then
        ls -l /etc/cron* 2>/dev/null | tee -a "$REPORT_FILE"
    else
        echo "No /etc/cron* directories or files found." | tee -a "$REPORT_FILE"
    fi
    
    # Installed packages with count
    echo "Installed Packages:" | tee -a "$REPORT_FILE"
    if [ "$PKG_MANAGER" != "unknown" ]; then 
        local pkg_count=$($QUERY_CMD 2>/dev/null | wc -l)
        echo "Total packages: $pkg_count" | tee -a "$REPORT_FILE"
        if ! $QUERY_CMD | tee -a "$REPORT_FILE"; then
            log_warn "Listing packages with $PKG_MANAGER encountered an error."
        fi
        log_info "Listed $pkg_count installed packages."
    else 
        echo "No package manager detected; unable to list installed packages." | tee -a "$REPORT_FILE"
    fi
    
    # Rootkit scanners
    if command -v chkrootkit &> /dev/null; then 
        log_info "Running chkrootkit scan..."
        if ! chkrootkit 2>&1 | tee -a "$REPORT_FILE"; then
            log_warn "chkrootkit returned a non-zero status; review scan output."
        fi
    elif command -v rkhunter &> /dev/null; then 
        log_info "Running rkhunter scan..."
        if ! rkhunter --check 2>&1 | tee -a "$REPORT_FILE"; then
            log_warn "rkhunter returned a non-zero status; review scan output."
        fi
    else 
        log_warn "No rootkit scanner (chkrootkit/rkhunter) found. For threat hunting, install one: apt install chkrootkit (Debian) or dnf/yum install rkhunter (Fedora/CentOS)."
    fi
    log_info "Security info complete."
}

# 8. All Enumerations
enum_all() {
    enum_system_overview
    enum_users_auth
    enum_network
    enum_processes_services
    enum_logs
    enum_filesystem
    enum_security
}

# --- Prompt for Enumeration Mode ---
prompt_mode() {
    > "$REPORT_FILE"  # Clear report file
    append_to_report "System Enumeration Report - Generated $TIMESTAMP"
    log_info "Select enumeration category:"
    echo "1) System Overview"
    echo "2) Users and Authentication"
    echo "3) Network Information"
    echo "4) Processes and Services"
    echo "5) Logs and Monitoring"
    echo "6) File System and Integrity"
    echo "7) Security Tools and Configurations"
    echo "8) All of the Above"
    read -p "Enter your choice (1-8): " choice
    case "$choice" in
        1) enum_system_overview ;;
        2) enum_users_auth ;;
        3) enum_network ;;
        4) enum_processes_services ;;
        5) enum_logs ;;
        6) enum_filesystem ;;
        7) enum_security ;;
        8) enum_all ;;
        *) log_error "Invalid choice. Please select 1-8." ;;
    esac
    log_info "Enumeration complete. Report saved to $REPORT_FILE."
    
    # New: Summary to confirm output
    local report_lines=$(wc -l < "$REPORT_FILE")
    log_info "Report summary: $report_lines lines generated. Check for anomalies in key sections (e.g., unknown cron jobs, open ports)."
    
    read -p "View report now? (y/n): " view
    if [[ $view =~ ^[Yy]$ ]]; then cat "$REPORT_FILE"; fi
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "Use this report for incident reporting or threat hunting. Review for anomalies like unknown users, open ports, or suspicious processes."
}

main "$@"