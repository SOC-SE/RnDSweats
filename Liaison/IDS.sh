#!/bin/bash

# ============================================================================== 
# File: IDS.sh 
# Description: Installs, uninstalls, configures, and adjusts Suricata as IDS or IPS.
#              Menu-driven with install/uninstall/adjust/quit options. Supports apt and dnf.
#              Spinner for install/uninstall, error capture, usage instructions aligned with MWCCDC.
#              Adjust option for CCDC-related configurations, with apply/revert and status display.
# ============================================================================== 

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
#################################################
# ____             _           _                #
#/ ___| _   _ _ __(_) ___ __ _| |_ __ _         #
#\___ \| | | | '__| |/ __/ _` | __/ _` |  _____ #
# ___) | |_| | |  | | (_| (_| | || (_| | |_____|#
#|____/ \__,_|_|  |_|\___\__,_|\__\__,_|        #
# ___ ____  ____    _____ ____  ____            #
#|_ _|  _ \/ ___|  / /_ _|  _ \/ ___|           #
# | || | | \___ \ / / | || |_) \___ \           #
# | || |_| |___) / /  | ||  __/ ___) |          #
#|___|____/|____/_/  |___|_|   |____/           #
#################################################
EOF
echo -e "\033[0m"
echo "IDS/IPS Manager"
echo "--------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
CONFIG_FILE="/etc/suricata/suricata.yaml"
STATE_FILE="/etc/suricata/adjustments.state"  # To track applied adjustments

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function
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
        UPDATE_CMD="dnf makecache -y"
        QUERY_CMD="rpm -q"
        REMOVE_CMD="dnf remove -y"
    else
        log_error "Unsupported package manager. Only apt and dnf supported."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Check if Suricata Installed ---
is_suricata_installed() {
    command -v suricata &> /dev/null
}

# --- Install Suricata (as IDS or IPS) ---
install_suricata() {
    local mode=$1  # IDS or IPS
    if is_suricata_installed; then
        log_warn "Suricata is already installed."
        return 1
    fi
    log_info "Installing Suricata as $mode..."
    printf "Installing Suricata... "
    local err_file=$(mktemp)
    if [ "$PKG_MANAGER" = "apt" ]; then
        ( $UPDATE_CMD >/dev/null 2>"$err_file"
          $INSTALL_CMD suricata >/dev/null 2>>"$err_file" ) &
    else
        if [ -r /etc/os-release ]; then
            . /etc/os-release
            case "$ID" in
                ol)
                    dnf install -y "oracle-epel-release-el${VERSION_ID%%.*}" >/dev/null 2>>"$err_file" || true
                    ;;
                centos|rhel|rocky|almalinux)
                    dnf install -y epel-release >/dev/null 2>>"$err_file" || true
                    ;;
            esac
        fi
        ( $INSTALL_CMD suricata >/dev/null 2>>"$err_file" ) &
    fi
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during Suricata installation:${NC}"
        echo "$err_content"
        log_error "Installation failed."
    fi
    echo ""  # Newline

    # Post-install with spinner and error capture
    printf "Configuring Suricata... "
    local err_file=$(mktemp)
            ( suricata-update >/dev/null 2>"$err_file" || true
                configure_suricata_initial "$mode" >/dev/null 2>>"$err_file"
      systemctl enable suricata >/dev/null 2>>"$err_file"
      systemctl start suricata >/dev/null 2>>"$err_file" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during Suricata configuration:${NC}"
        echo "$err_content"
        log_error "Configuration failed."
    fi
    echo ""  # Newline

    print_usage_instructions $mode
    return 0
}

# --- Initial Configuration ---
configure_suricata_initial() {
    local mode=$1
    log_info "Available interfaces:"
    ip link show | grep -E '^[0-9]+: ' | awk -F: '{print $2}' | tr -d ' '
    read -p "Enter network interface (e.g., eth0 or ens192): " INTERFACE
    if [ -z "$INTERFACE" ] || ! ip link show "$INTERFACE" > /dev/null 2>&1; then
        log_error "Invalid interface: $INTERFACE"
    fi
    read -p "Enter HOME_NET CIDR (e.g., 172.20.240.0/24): " CIDR
    if [[ ! "$CIDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        log_error "Invalid CIDR: $CIDR"
    fi
    sed -i "s/^  HOME_NET: .*/  HOME_NET: \"[$CIDR]\"/" "$CONFIG_FILE" >/dev/null 2>&1
    sed -i "s/^  EXTERNAL_NET: .*/  EXTERNAL_NET: \"!\$HOME_NET\"/" "$CONFIG_FILE" >/dev/null 2>&1
    sed -i "/^af-packet:/,/^  - interface:/s/^  - interface: .*/  - interface: $INTERFACE/" "$CONFIG_FILE" >/dev/null 2>&1
    if [ "$mode" = "IPS" ]; then
        sed -i 's/^inline: no/inline: yes/' "$CONFIG_FILE" >/dev/null 2>&1 || echo 'inline: yes' >> "$CONFIG_FILE" >/dev/null 2>&1
    fi
    systemctl restart suricata >/dev/null 2>&1
}

# --- Uninstall Suricata ---
uninstall_suricata() {
    if ! is_suricata_installed; then
        log_warn "Suricata is not installed."
        return 1
    fi
    log_info "Uninstalling Suricata..."
    printf "Uninstalling Suricata... "
    local err_file=$(mktemp)
    ( systemctl stop suricata >/dev/null 2>"$err_file" || true
      systemctl disable suricata >/dev/null 2>>"$err_file" || true
      $REMOVE_CMD suricata >/dev/null 2>>"$err_file"
      rm -f "$STATE_FILE" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ -n "$err_content" ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Errors/Warnings:${NC}"
        echo "$err_content"
    fi
    if [ $exit_status -ne 0 ]; then
        log_error "Uninstallation failed."
    fi
    if [ -z "$err_content" ]; then
        echo ""  # Newline only if no errors
    fi
    log_info "Suricata uninstalled."
    return 0
}

# --- Print Usage Instructions ---
print_usage_instructions() {
    local mode=$1
    log_info "Suricata installed and started as $mode on your interface."
    log_info "How to utilize service:"
    echo "  - Monitor alerts for Red Team activity: tail -f /var/log/suricata/fast.log"
    echo "  - Update rules regularly: suricata-update (use pre-approved sources only, no internet installs)."
    echo "  - Test config: suricata -T -c $CONFIG_FILE"
    echo "  - For detection/response: Focus on logging exploitation events for IR reports. Avoid any active scans/offensive actions (disqualification risk)."
    echo "  - In IPS mode: Inline blocking helps maintain service uptime/scoring but test to avoid disrupting business tasks."
    echo "  - Expose via Palo Alto if needed (e.g., NAT to public IPs per topology)."
    log_warn "Harden: Restrict access, monitor for false positives impacting services."
}

# --- Adjust Service ---
adjust_service() {
    if ! is_suricata_installed; then
        log_warn "Suricata not installed. Install first."
        return
    fi
    mkdir -p "$(dirname "$STATE_FILE")"
    touch "$STATE_FILE"
    local adjustments=(
        "Enable verbose logging (for detailed IR)"
        "Add custom rule for SSH brute-force (common Red Team tactic)"
        "Set high-performance mode (for busy networks)"
        "Enable Eve JSON logging (advanced analysis for scoring)"
    )
    log_info "Current adjustments in effect:"
    cat "$STATE_FILE" 2>/dev/null || echo "None applied."
    log_info "Select adjustment to apply or revert (0 to exit):"
    for i in "${!adjustments[@]}"; do
        echo "$((i+1))) ${adjustments[i]}"
    done
    read -p "Enter choice: " choice
    if [ "$choice" -eq 0 ]; then return; fi
    if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#adjustments[@]}" ]; then
        log_warn "Invalid choice."
        return
    fi
    local adj="${adjustments[$((choice-1))]}"
    if grep -q "^$adj$" "$STATE_FILE"; then
        revert_adjustment "$adj"
    else
        apply_adjustment "$adj"
    fi
    systemctl restart suricata
    log_info "Adjustment applied/reverted. Service restarted."
}

apply_adjustment() {
    local adj=$1
    case "$adj" in
        "Enable verbose logging (for detailed IR)")
            sed -i 's/logging-level: info/logging-level: debug/' "$CONFIG_FILE" ;;
        "Add custom rule for SSH brute-force (common Red Team tactic)")
            mkdir -p /etc/suricata/rules
            echo 'alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; flow:to_server; threshold: type both, track by_src, count 5, seconds 60; sid:1000001;)' >> /etc/suricata/rules/custom.rules
            sed -i '/rule-files:/ a\  - custom.rules' "$CONFIG_FILE" ;;
        "Set high-performance mode (for busy networks)")
            sed -i 's/^cpu-affinity: no/cpu-affinity: yes/' "$CONFIG_FILE" || echo 'cpu-affinity: yes' >> "$CONFIG_FILE" ;;
        "Enable Eve JSON logging (advanced analysis for scoring)")
            sed -i '/eve-log:/,/enabled:/ s/enabled: no/enabled: yes/' "$CONFIG_FILE" ;;
    esac
    echo "$adj" >> "$STATE_FILE"
    log_info "Applied: $adj"
}

revert_adjustment() {
    local adj=$1
    case "$adj" in
        "Enable verbose logging (for detailed IR)")
            sed -i 's/logging-level: debug/logging-level: info/' "$CONFIG_FILE" ;;
        "Add custom rule for SSH brute-force (common Red Team tactic)")
            sed -i '/- custom.rules/d' "$CONFIG_FILE"
            rm -f /etc/suricata/rules/custom.rules ;;
        "Set high-performance mode (for busy networks)")
            sed -i 's/^cpu-affinity: yes/cpu-affinity: no/' "$CONFIG_FILE" ;;
        "Enable Eve JSON logging (advanced analysis for scoring)")
            sed -i '/eve-log:/,/enabled:/ s/enabled: yes/enabled: no/' "$CONFIG_FILE" ;;
    esac
    sed -i "/^$adj$/d" "$STATE_FILE"
    log_info "Reverted: $adj (service restored to pre-adjustment state)."
}

# --- Menu ---
prompt_menu() {
    while true; do
        log_info "Select option:"
        echo "1) Install (IDS or IPS)"
        echo "2) Uninstall"
        echo "3) Adjust Service"
        echo "4) Quit"
        read -p "Enter choice (1-4): " opt
        case $opt in
            1) read -p "Install as IDS (1) or IPS (2)? " type
               if [ "$type" = "1" ]; then install_suricata "IDS"
               elif [ "$type" = "2" ]; then install_suricata "IPS"
               else log_warn "Invalid choice."; fi ;;
            2) uninstall_suricata ;;
            3) adjust_service ;;
            4) log_info "Exiting."; exit 0 ;;
            *) log_warn "Invalid choice." ;;
        esac
    done
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    prompt_menu
}

main "$@"