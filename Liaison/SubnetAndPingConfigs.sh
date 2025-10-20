# ==============================================================================
# File: SubnetAndPingConfigs.sh
# Description: Provides tools for subnetting IPv4 and IPv6 networks, and configuring ping connectivity between two machines in a CCDC environment.
#              Supports calculation of subnets from a given network and prefix. For connectivity, prompts for interface, calculates and assigns IPs from a subnet,
#              configures firewall rules to allow ICMP (ping) for IPv4/IPv6, and tests ping to a remote IP. Assumes the script is run on both machines with complementary IPs.
#              Supports install/calculate mode for subnetting, configure mode for enabling ping, remove mode for undoing configurations, and view mode for displaying current setups.
#              Detects and handles Debian/Ubuntu (apt) and Fedora/CentOS (dnf). Installs required tools like ipcalc (for IPv4) and sipcalc (for IPv6) if missing.
#              Configurations are applied temporarily (via ip command) and can be removed. For persistence, use netplan/networkmanager manually.
#              In CCDC, use for quick subnetting and testing connectivity between team-controlled machines (e.g., internal links).
#
# Dependencies: ipcalc (IPv4 subnetting), sipcalc (IPv6 subnetting) - installed automatically if missing.
# Usage: sudo ./SubnetAndPingConfigurator.sh
#        Follow prompts to select mode (calculate, configure, remove, view).
# Notes: 
# - Run as root.
# - For two-machine setup: Run on Machine A to assign local IP, then on Machine B with complementary remote IP as local.
# - Ping test uses 'ping' for IPv4 and 'ping6' for IPv6.
# - Firewall rules added for ufw/firewalld if present; assumes ICMP is for ping.
# - Subnet calculations are displayed; no files saved by default.
# ==============================================================================

#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
 ____        _                _     ___ ____  
/ ___| _   _| |__  _ __   ___| |_  |_ _|  _ \ 
\___ \| | | | '_ \| '_ \ / _ \ __|  | || |_) |
 ___) | |_| | |_) | | | |  __/ |_   | ||  __/ 
|____/ \__,_|_.__/|_| |_|\___|\__| |___|_|    
__        ___                  _              
\ \      / (_)______ _ _ __ __| |             
 \ \ /\ / /| |_  / _` | '__/ _` |             
  \ V  V / | |/ / (_| | | | (_| |             
   \_/\_/  |_/___\__,_|_|  \__,_|             
EOF
echo -e "\033[0m"
echo "Subnet and Ping Configurator - For CCDC Team Prep"
echo "-------------------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function for progress
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
        UPDATE_CMD="dnf check-update"
        QUERY_CMD="rpm -q"
        REMOVE_CMD="dnf remove -y"
    else
        log_error "Unsupported package manager. Only apt (Debian/Ubuntu) and dnf (Fedora/CentOS) are supported."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Install Required Tools ---
install_tools() {
    local tools=("ipcalc" "sipcalc")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_info "Installing $tool..."
            $UPDATE_CMD >/dev/null 2>&1
            $INSTALL_CMD "$tool" >/dev/null 2>&1 &
            spinner $!
        fi
    done
}

# TeamPack compliance: confirm authorized environment
teampack_confirm() {
    read -p "Confirm you will run this only on your authorized team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}
teampack_confirm

# --- Calculate IPv4 Subnets ---
calculate_ipv4_subnets() {
    read -p "Enter IPv4 network (e.g., 192.168.1.0/24): " network
    read -p "Enter new subnet prefix (e.g., 26): " new_prefix
    if ! ipcalc "$network" >/dev/null 2>&1; then
        log_error "Invalid IPv4 network provided."
    fi
    if [[ ! $new_prefix =~ ^[0-9]+$ ]] || (( new_prefix < 0 || new_prefix > 32 )); then
        log_error "New prefix must be an integer between 0 and 32."
    fi
    local original_prefix=${network##*/}
    if (( new_prefix < original_prefix )); then
        log_error "New prefix must be greater than or equal to original prefix /$original_prefix."
    fi
    local diff=$((new_prefix - original_prefix))
    local subnet_count=$(( diff == 0 ? 1 : (1 << diff) ))
    ipcalc "$network" -s "$subnet_count" | grep -E 'Network|HostMin|HostMax|Broadcast'
}

# --- Calculate IPv6 Subnets ---
calculate_ipv6_subnets() {
    read -p "Enter IPv6 network (e.g., 2001:db8::/64): " network
    read -p "Enter new subnet prefix (e.g., 68): " new_prefix
    if ! sipcalc "$network" >/dev/null 2>&1; then
        log_error "Invalid IPv6 network provided."
    fi
    if [[ ! $new_prefix =~ ^[0-9]+$ ]] || (( new_prefix < 0 || new_prefix > 128 )); then
        log_error "New prefix must be an integer between 0 and 128."
    fi
    local original_prefix=${network##*/}
    if (( new_prefix < original_prefix )); then
        log_error "New prefix must be greater than or equal to original prefix /$original_prefix."
    fi
    sipcalc "$network" -s "$new_prefix" | grep -E 'Network range|Usable range'
}

# --- Configure IPv4 Ping ---
configure_ipv4_ping() {
    read -p "Enter interface (e.g., eth0): " iface
    read -p "Enter local IPv4 from subnet (e.g., 192.168.1.1/26): " local_ip
    read -p "Enter remote IPv4 (e.g., 192.168.1.2): " remote_ip

    ip addr add "$local_ip" dev "$iface"
    log_info "Assigned $local_ip to $iface."

    # Firewall allow ICMP
    if command -v ufw &> /dev/null; then
        ufw allow proto icmp from any to any
        ufw reload
        log_info "UFW rule added for ICMPv4."
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-protocol=icmp
        firewall-cmd --reload
        log_info "Firewalld rule added for ICMPv4."
    else
        log_warn "No supported firewall; ensure ICMP is allowed manually."
    fi

    # Test ping
    if ping -c 3 "$remote_ip" &> /dev/null; then
        log_info "Ping to $remote_ip successful."
    else
        log_warn "Ping to $remote_ip failed. Check remote config."
    fi
}

# --- Configure IPv6 Ping ---
configure_ipv6_ping() {
    read -p "Enter interface (e.g., eth0): " iface
    read -p "Enter local IPv6 from subnet (e.g., 2001:db8::1/68): " local_ip
    read -p "Enter remote IPv6 (e.g., 2001:db8::2): " remote_ip

    ip -6 addr add "$local_ip" dev "$iface"
    log_info "Assigned $local_ip to $iface."

    # Firewall allow ICMPv6
    if command -v ufw &> /dev/null; then
        ufw allow proto ipv6-icmp from any to any || ufw allow ipv6-icmp
        ufw reload
        log_info "UFW rule added for ICMPv6."
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-protocol=ipv6-icmp
        firewall-cmd --reload
        log_info "Firewalld rule added for ICMPv6."
    else
        log_warn "No supported firewall; ensure ICMPv6 is allowed manually."
    fi

    # Test ping
    if ping6 -c 3 "$remote_ip" &> /dev/null; then
        log_info "Ping6 to $remote_ip successful."
    else
        log_warn "Ping6 to $remote_ip failed. Check remote config."
    fi
}

# --- Remove IPv4 Config ---
remove_ipv4_config() {
    read -p "Enter interface (e.g., eth0): " iface
    read -p "Enter local IPv4 to remove (e.g., 192.168.1.1/26): " local_ip

    ip addr del "$local_ip" dev "$iface"
    log_info "Removed $local_ip from $iface."

    # Remove firewall rule (approximate reversal)
    if command -v ufw &> /dev/null; then
        ufw delete allow proto icmp from any to any
        ufw reload
        log_info "UFW ICMPv4 rule removed."
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-protocol=icmp
        firewall-cmd --reload
        log_info "Firewalld ICMPv4 rule removed."
    fi
}

# --- Remove IPv6 Config ---
remove_ipv6_config() {
    read -p "Enter interface (e.g., eth0): " iface
    read -p "Enter local IPv6 to remove (e.g., 2001:db8::1/68): " local_ip

    ip -6 addr del "$local_ip" dev "$iface"
    log_info "Removed $local_ip from $iface."

    # Remove firewall rule
    if command -v ufw &> /dev/null; then
        ufw delete allow proto ipv6-icmp from any to any
        ufw reload
        log_info "UFW ICMPv6 rule removed."
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-protocol=ipv6-icmp
        firewall-cmd --reload
        log_info "Firewalld ICMPv6 rule removed."
    fi
}

# --- View Current Configs ---
view_configs() {
    log_info "Current IPv4 addresses:"
    ip -4 addr show
    log_info "Current IPv6 addresses:"
    ip -6 addr show
    log_info "Firewall rules (if ufw):"
    command -v ufw &> /dev/null && ufw status || echo "UFW not installed."
    log_info "Firewall rules (if firewalld):"
    command -v firewall-cmd &> /dev/null && firewall-cmd --list-all || echo "Firewalld not installed."
}

# --- Prompt for Mode ---
prompt_mode() {
    log_info "Select mode:"
    echo "1) Calculate subnets"
    echo "2) Configure ping connectivity"
    echo "3) Remove configurations"
    echo "4) View current configurations"
    read -p "Enter your choice (1-4): " mode
    case "$mode" in
        1) calculate_mode ;;
        2) configure_mode ;;
        3) remove_mode ;;
        4) view_configs ;;
        *) log_error "Invalid choice. Please select 1-4." ;;
    esac
}

# --- Calculate Mode ---
calculate_mode() {
    log_info "Select protocol:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice (1-2): " proto
    case "$proto" in
        1) calculate_ipv4_subnets ;;
        2) calculate_ipv6_subnets ;;
        *) log_error "Invalid choice." ;;
    esac
}

# --- Configure Mode ---
configure_mode() {
    log_info "Select protocol:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice (1-2): " proto
    case "$proto" in
        1) configure_ipv4_ping ;;
        2) configure_ipv6_ping ;;
        *) log_error "Invalid choice." ;;
    esac
}

# --- Remove Mode ---
remove_mode() {
    log_info "Select protocol:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice (1-2): " proto
    case "$proto" in
        1) remove_ipv4_config ;;
        2) remove_ipv6_config ;;
        *) log_error "Invalid choice." ;;
    esac
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    install_tools
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "Remember to verify configurations and harden for CCDC."
}

main "$@"