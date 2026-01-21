#!/bin/bash

# ============================================================================== 
# File: IDS.sh 
# Description: Installs, uninstalls, configures, and adjusts Suricata as IDS or IPS.
#              Menu-driven with install/uninstall/adjust/quit options. Supports apt and dnf.
#              Spinner for install/uninstall, error capture, usage instructions aligned with best practices.
#              Adjust option for custom configurations, with apply/revert and status display.
# ============================================================================== 

# IDS Script

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
echo "---------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
CONFIG_FILE="/etc/suricata/suricata.yaml"
STATE_FILE="/etc/suricata/adjustments.state"

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

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

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

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

is_suricata_installed() {
    command -v suricata &> /dev/null
}

install_suricata() {
    local mode=$1
    is_suricata_installed && { log_warn "Suricata already installed."; return 1; }
    log_info "Installing Suricata as $mode..."
    printf "Installing Suricata... "
    local err_file=$(mktemp)
    if [ "$PKG_MANAGER" = "apt" ]; then
        ( $UPDATE_CMD >/dev/null 2>"$err_file"
          $INSTALL_CMD suricata >/dev/null 2>>"$err_file" ) &
    else
        ( $INSTALL_CMD epel-release >/dev/null 2>"$err_file" || true
          $INSTALL_CMD suricata >/dev/null 2>>"$err_file" ) &
    fi
    spinner $!
    wait
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    [ $exit_status -ne 0 ] && {
        echo ""
        echo -e "${RED}Error during Suricata installation:${NC}"
        echo "$err_content"
        log_error "Installation failed."
    }
    echo ""
    printf "Configuring Suricata... "
    local err_file=$(mktemp)
    ( suricata-update >/dev/null 2>"$err_file" || true
      configure_suricata_initial "$mode" >/dev/null 2>>"$err_file"
      systemctl enable suricata >/dev/null 2>>"$err_file"
      systemctl start suricata >/dev/null 2>>"$err_file" ) &
    spinner $!
    wait
    rm -f "$err_file"
    print_usage_instructions "$mode"
}

configure_suricata_initial() {
    local mode=$1
    log_info "Available interfaces:"
    ip link show | grep -E '^[0-9]+: ' | awk -F: '{print $2}' | tr -d ' '
    read -p "Enter network interface (e.g., eth0): " INTERFACE
    [[ -z $INTERFACE || ! ip link show "$INTERFACE" > /dev/null 2>&1 ]] && log_error "Invalid interface."
    read -p "Enter HOME_NET CIDR (e.g., 172.20.240.0/24): " CIDR
    [[ ! $CIDR =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] && log_error "Invalid CIDR."
    sed -i "s/^  HOME_NET: .*/  HOME_NET: \"[$CIDR]\"/; /^  EXTERNAL_NET: .*/s//  EXTERNAL_NET: \"!\$HOME_NET\"/" "$CONFIG_FILE"
    sed -i "/^af-packet:/,/^  - interface:/s/^  - interface: .*/  - interface: $INTERFACE/" "$CONFIG_FILE"
    [[ $mode = "IPS" ]] && sed -i 's/^inline: no/inline: yes/' "$CONFIG_FILE" || echo 'inline: yes' >> "$CONFIG_FILE"
    systemctl restart suricata >/dev/null 2>&1
}

uninstall_suricata() {
    ! is_suricata_installed && { log_warn "Suricata not installed."; return 1; }
    log_info "Uninstalling Suricata..."
    printf "Uninstalling Suricata... "
    local err_file=$(mktemp)
    ( systemctl stop suricata >/dev/null 2>"$err_file" || true
      systemctl disable suricata >/dev/null 2>>"$err_file" || true
      $REMOVE_CMD suricata >/dev/null 2>>"$err_file"
      rm -f "$STATE_FILE" ) &
    spinner $!
    wait
    rm -f "$err_file"
    log_info "Suricata uninstalled."
}

print_usage_instructions() {
    local mode=$1
    log_info "Suricata $mode started."
    log_info "Monitor: tail -f /var/log/suricata/fast.log"
    log_info "Update rules: suricata-update"
    log_info "Test config: suricata -T -c $CONFIG_FILE"
    log_warn "Restrict access, monitor false positives."
}

adjust_service() {
    is_suricata_installed || { log_warn "Suricata not installed."; return; }
    mkdir -p "$(dirname "$STATE_FILE")"
    touch "$STATE_FILE"
    local adjustments=( "Enable verbose logging" "Add SSH brute-force rule" "High-performance mode" "Eve JSON logging" )
    log_info "Current adjustments:"
    cat "$STATE_FILE" 2>/dev/null || echo "None."
    log_info "Select (0 exit):"
    for i in "${!adjustments[@]}"; do echo "$((i+1))) ${adjustments[i]}"; done
    read -p "Choice: " choice
    [[ $choice -eq 0 ]] && return
    [[ $choice -lt 1 || $choice -gt ${#adjustments[@]} ]] && { log_warn "Invalid."; return; }
    local adj="${adjustments[$((choice-1))]}"
    if grep -q "^$adj$" "$STATE_FILE"; then
        revert_adjustment "$adj"
    else
        apply_adjustment "$adj"
    fi
    systemctl restart suricata
}

apply_adjustment() {
    local adj=$1
    case "$adj" in
        "Enable verbose logging") sed -i 's/logging-level: info/logging-level: debug/' "$CONFIG_FILE" ;;
        "Add SSH brute-force rule")
            mkdir -p /etc/suricata/rules
            echo 'alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; flow:to_server; threshold: type both, track by_src, count 5, seconds 60; sid:1000001;)' >> /etc/suricata/rules/custom.rules
            sed -i '/rule-files:/ a\  - custom.rules' "$CONFIG_FILE" ;;
        "High-performance mode") sed -i 's/^cpu-affinity: no/cpu-affinity: yes/' "$CONFIG_FILE" || echo 'cpu-affinity: yes' >> "$CONFIG_FILE" ;;
        "Eve JSON logging") sed -i '/eve-log:/,/enabled:/ s/enabled: no/enabled: yes/' "$CONFIG_FILE" ;;
    esac
    echo "$adj" >> "$STATE_FILE"
}

revert_adjustment() {
    local adj=$1
    case "$adj" in
        "Enable verbose logging") sed -i 's/logging-level: debug/logging-level: info/' "$CONFIG_FILE" ;;
        "Add SSH brute-force rule")
            sed -i '/- custom.rules/d' "$CONFIG_FILE"
            rm -f /etc/suricata/rules/custom.rules ;;
        "High-performance mode") sed -i 's/^cpu-affinity: yes/cpu-affinity: no/' "$CONFIG_FILE" ;;
        "Eve JSON logging") sed -i '/eve-log:/,/enabled:/ s/enabled: yes/enabled: no/' "$CONFIG_FILE" ;;
    esac
    sed -i "/^$adj$/d" "$STATE_FILE"
}

prompt_menu() {
    while true; do
        log_info "Select option:"
        echo "1) Install (IDS or IPS)"
        echo "2) Uninstall"
        echo "3) Adjust Service"
        echo "4) Quit"
        read -p "Choice (1-4): " opt
        case $opt in
            1) read -p "IDS (1) or IPS (2)? " type; [[ $type = "1" ]] && install_suricata "IDS" || install_suricata "IPS" ;;
            2) uninstall_suricata ;;
            3) adjust_service ;;
            4) log_info "Exiting."; exit 0 ;;
            *) log_warn "Invalid." ;;
        esac
    done
}

main() {
    check_root
    detect_pkg_manager
    prompt_menu
}

main "$@"