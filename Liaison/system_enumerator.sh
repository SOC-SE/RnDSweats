# ==============================================================================
# File: System_Enumerator.sh
# Description: Performs advanced enumeration on a Linux machine for CCDC competitions.
#              Prompts the user to select categories of information to gather, such as system overview, users, network, processes, logs, etc.
#              Gathers verbose details for injects, incident reporting, and threat hunting. Checks for key indicators like suspicious processes,
#              open ports, cron jobs, installed packages, and potential security issues. Outputs to console and optionally saves to a report file.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS (dnf) for compatibility with CCDC VMs.
#              Designed to align with Perfect Box Framework (PBF) elements like System Pruning, Log Aggregation, IDS, and threat hunting.
#
# Dependencies: Standard Linux tools (e.g., ps, netstat/ss, awk, grep). Optional: chkrootkit or rkhunter for rootkit detection (prompts if not installed).
# Usage: sudo ./System_Enumerator.sh
#        Follow on-screen prompts to select enumeration categories.
# Notes: 
# - Run as root for full access (e.g., to /etc/shadow, raw sockets).
# - In CCDC, use this to baseline systems, detect red team artifacts, and generate reports for injects.
# - Outputs are timestamped and can be exported to /tmp/enum_report.txt for easy sharing.
# - For threat hunting: Looks for common persistence mechanisms (e.g., cron, unusual users, listening ports).
# ==============================================================================

#!/bin/bash

set -euo pipefail

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
echo "System Enumerator - For CCDC Threat Hunting and Reporting"
echo "---------------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
REPORT_FILE="/tmp/enum_report.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function for progress (used for longer commands)
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "%c " "${spinstr:0:1}"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b"
    done
    printf " \b"
}

append_to_report() {
    echo "$1" >> "$REPORT_FILE"
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
    uname -a >> "$REPORT_FILE"
    if command -v hostnamectl &> /dev/null; then hostnamectl >> "$REPORT_FILE"; fi
    if command -v lsb_release &> /dev/null; then lsb_release -a >> "$REPORT_FILE"; fi
    uptime >> "$REPORT_FILE"
    df -h >> "$REPORT_FILE"
    free -h >> "$REPORT_FILE"
    log_info "System overview complete."
}

# 2. Users and Authentication
enum_users_auth() {
    log_info "Gathering Users and Authentication Info..."
    append_to_report "=== Users and Authentication ($TIMESTAMP) ==="
    cat /etc/passwd >> "$REPORT_FILE"
    cat /etc/group >> "$REPORT_FILE"
    if [ -r /etc/shadow ]; then awk -F: '{print $1 " has password? " ($2 != "" ? "Yes" : "No")}' /etc/shadow >> "$REPORT_FILE"; fi
    sudo -l >> "$REPORT_FILE" 2>&1
    lastlog >> "$REPORT_FILE"
    log_info "Users and auth info complete."
}

# 3. Network Information
enum_network() {
    log_info "Gathering Network Information..."
    append_to_report "=== Network Information ($TIMESTAMP) ==="
    ip addr show >> "$REPORT_FILE"
    ip route >> "$REPORT_FILE"
    if command -v ss &> /dev/null; then ss -tuln >> "$REPORT_FILE"; else netstat -tuln >> "$REPORT_FILE"; fi
    arp -a >> "$REPORT_FILE"
    if command -v iptables &> /dev/null; then iptables -L -n -v >> "$REPORT_FILE"; fi
    if command -v ufw &> /dev/null; then ufw status verbose >> "$REPORT_FILE"; fi
    if command -v firewall-cmd &> /dev/null; then firewall-cmd --list-all >> "$REPORT_FILE"; fi
    log_info "Network info complete."
}

# 4. Processes and Services
enum_processes_services() {
    log_info "Gathering Processes and Services..."
    append_to_report "=== Processes and Services ($TIMESTAMP) ==="
    ps auxf >> "$REPORT_FILE"
    if command -v systemctl &> /dev/null; then systemctl list-units --type=service >> "$REPORT_FILE"; fi
    lsmod >> "$REPORT_FILE"
    log_info "Processes and services complete."
}

# 5. Logs and Monitoring
enum_logs() {
    log_info "Gathering Logs and Monitoring Info..."
    append_to_report "=== Logs and Monitoring ($TIMESTAMP) ==="
    if command -v journalctl &> /dev/null; then journalctl -n 50 >> "$REPORT_FILE"; fi
    tail -n 50 /var/log/auth.log 2>/dev/null >> "$REPORT_FILE" || tail -n 50 /var/log/secure 2>/dev/null >> "$REPORT_FILE"
    tail -n 50 /var/log/syslog 2>/dev/null >> "$REPORT_FILE" || tail -n 50 /var/log/messages 2>/dev/null >> "$REPORT_FILE"
    log_info "Logs info complete."
}

# 6. File System and Integrity
enum_filesystem() {
    log_info "Gathering File System and Integrity Info..."
    append_to_report "=== File System and Integrity ($TIMESTAMP) ==="
    find / -perm -4000 -type f 2>/dev/null >> "$REPORT_FILE"  # SUID files
    find /home -type f -name ".*" 2>/dev/null >> "$REPORT_FILE"  # Hidden files in home
    du -sh /var /home /etc 2>/dev/null >> "$REPORT_FILE"
    if command -v aide &> /dev/null; then aide --check >> "$REPORT_FILE" 2>&1; else log_warn "AIDE not installed for FIM."; fi
    log_info "File system info complete."
}

# 7. Security Tools and Configurations
enum_security() {
    log_info "Gathering Security Tools and Configurations..."
    append_to_report "=== Security Tools and Configurations ($TIMESTAMP) ==="
    crontab -l >> "$REPORT_FILE" 2>&1
    ls -l /etc/cron* >> "$REPORT_FILE" 2>&1
    if [ "$PKG_MANAGER" != "unknown" ]; then $QUERY_CMD >> "$REPORT_FILE"; fi
    if command -v chkrootkit &> /dev/null; then chkrootkit >> "$REPORT_FILE" 2>&1 & spinner $!; elif command -v rkhunter &> /dev/null; then rkhunter --check >> "$REPORT_FILE" 2>&1 & spinner $!; else log_warn "No rootkit scanner found. Install chkrootkit or rkhunter."; fi
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
    read -p "View report now? (y/n): " view
    if [[ $view =~ ^[Yy]$ ]]; then cat "$REPORT_FILE"; fi
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "Use this report for CCDC injects, incident reporting, or threat hunting. Review for anomalies like unknown users, open ports, or suspicious processes."
}

main "$@"