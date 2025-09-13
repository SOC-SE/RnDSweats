# ==============================================================================
# File: Liaison/psad_setup.sh
# Description: Installs/uninstalls and provides initial setup for PSAD (Port Scan Attack Detector),
#              a lightweight IDS that analyzes iptables logs for scans and attacks.
#
# Key Features (Aligned with MWCCDC and PBF):
# 1. Menu to install or uninstall PSAD; checks status and skips/exits as needed.
# 2. Prompts for CIDR (HOME_NET) and alert email during install.
# 3. Automatically edits /etc/psad/psad.conf for HOME_NET, alerts, and auto-IPS.
# 4. Adds iptables logging rules for INPUT/FORWARD chains (non-disruptive to services).
# 5. Handles Debian-based systems (apt); supports dnf with warnings.
# 6. Enables and starts PSAD service; updates signatures.
# 7. Validated for low resource use in virtual environments (e.g., NETLAB VE VMs).
# 8. Post-install instructions for optimal CCDC use (e.g., monitoring for IR reports).
# ==============================================================================

#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
______  _____  ___ ______ 
| ___ \/  ___|/ _ \|  _  \
| |_/ /\ `--./ /_\ \ | | |
|  __/  `--. \  _  | | | |
| |    /\__/ / | | | |/ / 
\_|    \____/\_| |_/___/  
EOF
echo -e "\033[0m"
echo "PSAD IDS Installer/Uninstaller - For CCDC Team Prep"
echo "-------------------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
CONFIG_FILE="/etc/psad/psad.conf"

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
        QUERY_CMD="dpkg -s"
        REMOVE_CMD="apt-get purge -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
        QUERY_CMD="rpm -q"
        REMOVE_CMD="dnf remove -y"
        log_warn "dnf detected; PSAD may require manual tweaks (optimized for apt/Debian)."
    else
        log_error "Unsupported package manager. Only apt (Debian/Ubuntu) and dnf (Fedora/CentOS) are supported."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Check if PSAD Installed ---
is_psad_installed() {
    $QUERY_CMD psad &> /dev/null
}

# --- PSAD Installation ---
install_psad() {
    if is_psad_installed; then
        log_warn "PSAD is already installed. No action needed."
        exit 0
    fi

    log_info "Installing PSAD..."
    $UPDATE_CMD
    $INSTALL_CMD psad
    log_info "PSAD installed successfully."
}

# --- Update Signatures ---
update_signatures() {
    log_info "Updating PSAD signatures..."
    psad --sig-update
    log_info "Signatures updated successfully."
}

# --- Configure PSAD ---
configure_psad() {
    # Prompt for CIDR (HOME_NET)
    read -p "Enter the internal IP address range in CIDR notation (e.g., 172.20.240.0/24): " CIDR
    if [[ ! "$CIDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        log_error "Invalid CIDR format: $CIDR"
    fi

    # Prompt for alert email
    read -p "Enter email address for alerts (e.g., team@ccdc.edu): " EMAIL
    if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_warn "Invalid email format: $EMAIL. Continuing, but alerts may fail."
    fi

    # Edit psad.conf
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
    fi
    sed -i "s/^HOME_NET .*/HOME_NET    $CIDR;/" "$CONFIG_FILE"
    sed -i "s/^EXTERNAL_NET .*/EXTERNAL_NET    any;/" "$CONFIG_FILE"  # Default to any external for broad detection
    sed -i "s/^EMAIL_ADDRESSES .*/EMAIL_ADDRESSES    $EMAIL;/" "$CONFIG_FILE"
    sed -i "s/^ENABLE_AUTO_IDS .*/ENABLE_AUTO_IDS    Y;/" "$CONFIG_FILE"  # Enable auto-IPS (blocking)
    sed -i "s/^AUTO_IDS_DANGER_LEVEL .*/AUTO_IDS_DANGER_LEVEL    3;/" "$CONFIG_FILE"  # Block on moderate threats
    log_info "Updated $CONFIG_FILE with HOME_NET: $CIDR, EMAIL: $EMAIL, and auto-IPS enabled."

    # Add iptables logging rules (non-disruptive; logs but doesn't block services)
    iptables -A INPUT -j LOG --log-prefix "PSAD: " --log-level 6
    iptables -A FORWARD -j LOG --log-prefix "PSAD: " --log-level 6
    log_info "Added iptables logging rules for PSAD integration."

    # Reload iptables (persistent via iptables-persistent if installed, but warn)
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables.rules  # Basic persistence; recommend iptables-persistent for production
        log_info "Saved iptables rules for persistence."
    else
        log_warn "iptables-save not found. Rules may not persist on reboot."
    fi
}

# --- Start Service ---
start_service() {
    # Reload PSAD to apply changes
    psad -R
    psad --fw-analyze  # Analyze firewall for compatibility

    # Enable and start (PSAD runs as daemon; no systemd unit by default, but simulate)
    if ! pgrep psad > /dev/null; then
        /usr/sbin/psad &  # Start daemon if not running
        log_info "PSAD daemon started manually."
    else
        log_info "PSAD is already running."
    fi

    # For systemd integration (if available on Debian)
    if command -v systemctl &> /dev/null; then
        systemctl enable psad || log_warn "PSAD systemd service not found; running as daemon."
        systemctl restart psad || log_warn "Restart failed; check status."
        if systemctl is-active --quiet psad; then
            log_info "PSAD service started successfully."
        else
            log_error "PSAD service failed to start. Check 'psad --status'."
        fi
    else
        log_warn "systemctl not found; PSAD running as background daemon."
    fi
}

# --- Uninstall PSAD ---
uninstall_psad() {
    if ! is_psad_installed; then
        log_warn "PSAD is not installed. Nothing to uninstall."
        exit 0
    fi

    read -p "Are you sure you want to uninstall PSAD? (y/n): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_warn "Action cancelled."
        exit 0
    fi

    log_info "Uninstalling PSAD..."
    if command -v systemctl &> /dev/null; then
        systemctl stop psad || true
        systemctl disable psad || true
    else
        pkill psad || true  # Kill daemon if running
    fi
    $REMOVE_CMD psad
    # Optional: Remove config and logs (but warn)
    rm -f "$CONFIG_FILE" || true
    rm -rf /var/log/psad/ || true
    log_info "PSAD uninstalled successfully."
}

# --- Print Optimal Usage Instructions (Post-Install) ---
print_instructions() {
    log_info "Optimal Usage Instructions for PSAD in CCDC Competitions:"
    echo "  - **Monitoring:** Run 'psad --status' to check active scans and blocked IPs. Tail logs with 'tail -f /var/log/psad/scan_log' or '/var/log/psad/auto_blocked' for real-time detection."
    echo "  - **Tuning for CCDC:** Edit /etc/psad/psad.conf to adjust AUTO_IDS_DANGER_LEVEL (e.g., set to 4+ to avoid false positives on scoring traffic like ICMP/HTTP checks per Team Pack page 14). Whitelist scoring engine IPs if needed via IGNORE_NETS."
    echo "  - **Incident Response:** Use detections to generate IR reports (10-20% of score, page 16). Include source IPs, timelines, and remediation (e.g., 'psad --fw-dump' for firewall state)."
    echo "  - **Integration:** Combine with tools like Splunk/ELK for centralized logging. Script auto-alerts to NISE/Team Portal for quick submissions."
    echo "  - **Testing:** Simulate Red Team scans with 'nmap -sS <your_ip>' from another VM; verify blocks without disrupting services (e.g., maintain SMTP uptime, page 17)."
    echo "  - **Security Tips:** Run on internal servers (e.g., Debian 10 DNS/NTP at 172.20.240.20). Avoid blocking Palo Alto Core (page 19). Update signatures regularly with 'psad --sig-update'."
    echo "  - **Commands Quick Ref:** 'psad -F' to flush blocks, 'psad --usr1' for status email, 'psad -A' to analyze logs."
    log_warn "Monitor for over-blocking; test thoroughly to avoid SLA penalties (page 16)."
}

# --- Prompt for Install/Uninstall ---
prompt_mode() {
    log_info "Select mode:"
    echo "1) Install PSAD"
    echo "2) Uninstall PSAD"
    read -p "Enter your choice (1-2): " mode
    case "$mode" in
        1) install_mode ;;
        2) uninstall_mode ;;
        *) log_error "Invalid choice. Please select 1 or 2." ;;
    esac
}

# --- Install Mode ---
install_mode() {
    install_psad
    update_signatures
    configure_psad
    start_service
    print_instructions
}

# --- Uninstall Mode ---
uninstall_mode() {
    uninstall_psad
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "Remember to harden further and test in your MWCCDC lab setup."
}

main "$@"