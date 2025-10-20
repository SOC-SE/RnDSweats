#!/bin/bash

set -euo pipefail

# ------------------------------------------------------------------------------
# TeamPack Compliance Notice
# This script is intended for use only against systems that you own or
# are explicitly authorized to test (your team lab / competition VMs).
# By continuing you confirm you will NOT use this tool to attack or scan
# other teams, public infrastructure, or systems you do not control.
# Refer to the MWCCDC Team Pack rules for permitted activity.
# ------------------------------------------------------------------------------
teampack_confirm() {
    echo ""
    echo "IMPORTANT: This script must only be used against systems you own or are authorized to test."
    read -p "I confirm I will only run this against my team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}

# Run TeamPack confirmation
teampack_confirm

# ==============================================================================
# File: install_vpns_2.sh
# Description: Installs and configures multiple VPN solutions (OpenVPN, WireGuard, SoftEther) on Linux.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS/RHEL (dnf).
#              Includes quick mode for faster installations with reduced security (e.g., 1024-bit DH for OpenVPN).
#              Menu-driven interface for install/uninstall/show instructions/show active services.
#              Provides connection instructions and active service status for multi-device connectivity.
#              Optimized for MWCCDC VMs; ensures proper service startup and firewall considerations.
#              Added: Client credential export, backups (PBF Core), enhanced error handling.
#
# Dependencies: apt (Debian/Ubuntu) or dnf (Fedora/CentOS/RHEL).
# Usage: sudo ./install_vpns_2.sh [--openvpn|--wireguard|--softether|--all|--quick]
#        Follow prompts if no flags provided.
# Notes: 
# - Run as root.
# - In CCDC, configure firewalls (e.g., Palo Alto NAT) and test connections.
# - Change default passwords and keys immediately for security.
# - SoftEther uses pre-built binaries for faster deployment (auto-download).
# ==============================================================================

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
 ___           _        _ _  __     ______  _   _ _ 
|_ _|_ __  ___| |_ __ _| | | \ \   / /  _ \| \ | | |
 | || '_ \/ __| __/ _` | | |  \ \ / /| |_) |  \| | |
 | || | | \__ \ || (_| | | |   \ V / |  __/| |\  |_|
|___|_| |_|___/\__\__,_|_|_|    \_/  |_|   |_| \_(_)
EOF
echo -e "\033[0m"
echo "VPN Nexus Installer - For CCDC Team Prep"
echo "---------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
LOG_FILE="/var/log/vpn_install.log"
QUICK_MODE=false
declare -a VPN_FLAGS=()  # Explicitly declare and initialize as array for older bash compatibility

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2 | tee -a "$LOG_FILE"; exit 1; }

# Spinner with timeout
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    local timeout=120  # Increased timeout for long operations like gen-dh
    local start_time=$(date +%s)
    while kill -0 $pid 2>/dev/null; do
        local elapsed=$(($(date +%s) - start_time))
        if [ $elapsed -ge $timeout ]; then
            log_warn "Spinner timeout reached ($timeout s)."
            break
        fi
        local temp=${spinstr#?}
        printf "%c  " "${spinstr:0:1}"  # Added space for better visibility
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b"  # Adjusted for the added space
    done
    printf "\n"
}

# Sanitize input
sanitize_input() { echo "$1" | tr -d '[:space:]'; }

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# Parse command-line flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick) QUICK_MODE=true; shift ;;
        --openvpn) VPN_FLAGS+=("openvpn"); shift ;;
        --wireguard) VPN_FLAGS+=("wireguard"); shift ;;
        --softether) VPN_FLAGS+=("softether"); shift ;;
        --all) VPN_FLAGS+=("openvpn" "wireguard" "softether"); shift ;;
        *) log_warn "Unknown option: $1"; shift ;;
    esac
done

# Fix dpkg interruptions (apt only); for dnf, check for locks
fix_dpkg() {
    log_info "Checking and fixing package manager interruptions..."
    if [[ "${PKG_MANAGER:-}" == "apt" ]]; then
        dpkg --configure -a >> "$LOG_FILE" 2>&1 || true
        apt-get install -f >> "$LOG_FILE" 2>&1 || true
    elif [[ "${PKG_MANAGER:-}" == "dnf" ]]; then
        # Remove lock files if present
        rm -f /var/run/dnf.pid /var/lib/dnf/history.lock || true
    fi
}

# Detect package manager
detect_pkg_manager() {
    if command -v apt >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt install -y"
        UPDATE_CMD="apt update -y"
        UPGRADE_CMD="apt upgrade -y"
        REMOVE_CMD="apt-get purge -y --autoremove"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
        UPGRADE_CMD="dnf upgrade -y"
        REMOVE_CMD="dnf remove -y"
    else
        log_error "Unsupported package manager (apt or dnf required)."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# Install dependencies including nc and ipcalc
install_dependencies() {
    log_info "Installing common dependencies..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $INSTALL_CMD curl wget git build-essential libssl-dev libreadline-dev zlib1g-dev libncurses5-dev netcat-openbsd ipcalc easy-rsa >/dev/null 2>&1 || \
        log_warn "Some dependencies failed to install, continuing..."
    else  # dnf
        $INSTALL_CMD curl wget git @development-tools openssl-devel readline-devel zlib-devel ncurses-devel nmap-ncat ipcalc easy-rsa >/dev/null 2>&1 || \
        log_warn "Some dependencies failed to install, continuing..."
    fi
    local missing=()
    for cmd in git curl nc ipcalc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Critical dependencies not available: ${missing[*]}. Install manually and rerun."
    fi
}

# Backup configs (PBF Core)
backup_configs() {
    local backup_dir="/backup/vpn_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    if [[ -d /etc/openvpn ]]; then rsync -a /etc/openvpn/ "$backup_dir/openvpn/" 2>/dev/null || true; fi
    if [[ -d /etc/wireguard ]]; then rsync -a /etc/wireguard/ "$backup_dir/wireguard/" 2>/dev/null || true; fi
    if [[ -d /usr/local/vpnserver ]]; then rsync -a /usr/local/vpnserver/ "$backup_dir/softether/" 2>/dev/null || true; fi
    log_info "Backups created in $backup_dir"
}

# Check if VPN Installed
is_openvpn_installed() { command -v openvpn >/dev/null 2>&1; }
is_wireguard_installed() { command -v wg >/dev/null 2>&1; }
is_softether_installed() { [[ -x /usr/local/vpnserver/vpnserver ]] && pgrep vpnserver >/dev/null 2>&1; }  # Check binary and process

all_installed() { is_openvpn_installed && is_wireguard_installed && is_softether_installed; }

# Prompt for Install/Uninstall
prompt_mode() {
    while true; do
        log_info "Select mode:"
        echo "1) Install a VPN"
        echo "2) Uninstall a VPN"
        echo "3) Show connection instructions"
        echo "4) Show active VPN services"
        echo "5) Certificate & User Management"
        echo "6) Run VPN Diagnostics"
        echo "7) Integration & Testing Help"
        echo "8) Exit"
        read -p "Enter your choice (1-8): " mode
        case "$mode" in
            1) install_mode ;;
            2) uninstall_mode ;;
            3) show_instructions_mode ;;
            4) show_active_services ;;
            5) show_certificate_management ;;
            6) run_vpn_diagnostics ;;
            7) show_integration_help ;;
            8) log_info "Exiting VPN Nexus Installer."; exit 0 ;;
            *) log_warn "Invalid choice." ;;
        esac
    done
}

# Install Mode with flag support
install_mode() {
    if all_installed && [ ${#VPN_FLAGS[@]} -eq 0 ]; then
        log_warn "All VPNs already installed."
        return 0
    fi
    if [ ${#VPN_FLAGS[@]} -gt 0 ]; then
        for vpn in "${VPN_FLAGS[@]}"; do
            if install_"$vpn"; then
                log_info "$vpn installed successfully."
            else
                log_error "$vpn installation failed."
            fi
        done
    else
        prompt_choice install
    fi
}

# Uninstall Mode
uninstall_mode() {
    if ! is_openvpn_installed && ! is_wireguard_installed && ! is_softether_installed; then
        log_warn "No VPNs installed."
        return 0
    fi
    if [ ${#VPN_FLAGS[@]} -gt 0 ]; then
        for vpn in "${VPN_FLAGS[@]}"; do
            uninstall_"$vpn"
        done
    else
        prompt_choice uninstall
    fi
}

show_instructions_mode() {
    local openvpn_installed=$(is_openvpn_installed && echo "Yes" || echo "No")
    local wireguard_installed=$(is_wireguard_installed && echo "Yes" || echo "No")
    local softether_installed=$(is_softether_installed && echo "Yes" || echo "No")
    
    log_info "Installed VPNs:"
    echo "OpenVPN: $openvpn_installed"
    echo "WireGuard: $wireguard_installed"
    echo "SoftEther: $softether_installed"
    
    if ! all_installed; then
        log_warn "Not all VPNs installed. Instructions may be incomplete."
    fi
    prompt_choice show
}

# Prompt User for VPN Choice
prompt_choice() {
    local action=$1
    local vpns=( "OpenVPN" "WireGuard" "SoftEther" )
    
    log_info "Select a VPN to $action:"
    for i in "${!vpns[@]}"; do echo "$((i+1))) ${vpns[$i]}"; done
    read -p "Enter your choice (1-3): " choice
    
    local vpn_index=$((choice - 1))
    if [ $vpn_index -lt 0 ] || [ $vpn_index -ge ${#vpns[@]} ]; then
        log_error "Invalid choice (1-3)."
    fi
    
    local vpn="${vpns[$vpn_index]}"
    
    if [ "$action" != "show" ]; then
        read -p "Sure to $action $vpn? (y/n): " confirm
        [[ "$confirm" =~ ^[yY]$ ]] || return 0
    fi
    
    local func_base=$(echo "$vpn" | tr '[:upper:]' '[:lower:]')
    local func
    if [ "$action" = "show" ]; then
        func="show_${func_base}_instructions"
    else
        local func_prefix=""
        if [ "$action" = "uninstall" ]; then func_prefix="un"; fi
        func="${func_prefix}install_${func_base}"
    fi
    $func || log_warn "$action $vpn completed with warnings."
}

# Update system (optional, but enable

update_system() { log_info "Skipping updates for efficiency."; }

# Install OpenVPN with client gen
install_openvpn() {
    backup_configs
    log_info "Installing OpenVPN..."
    printf "Installing... "
    local err_file=$(mktemp)
    ( $INSTALL_CMD openvpn easy-rsa >/dev/null 2>"$err_file" || exit 1
      if command -v make-cadir >/dev/null 2>&1; then
          make-cadir /etc/openvpn/easy-rsa >/dev/null 2>>"$err_file" || exit 1
      else
          mkdir -p /etc/openvpn >/dev/null 2>>"$err_file" || exit 1
          cp -r /usr/share/easy-rsa /etc/openvpn/easy-rsa >/dev/null 2>>"$err_file" || exit 1
      fi
      cd /etc/openvpn/easy-rsa >/dev/null 2>>"$err_file" || exit 1
      export EASYRSA_BATCH=1
      export EASYRSA_REQ_CN="MWCCDC-CA"
      ./easyrsa init-pki >/dev/null 2>>"$err_file" || exit 1
      ./easyrsa build-ca nopass >/dev/null 2>>"$err_file" || exit 1
      
      local dh_size=2048
      $QUICK_MODE && dh_size=1024 && log_warn "Quick mode: Using 1024-bit DH (less secure)."
      EASYRSA_DH_KEY_SIZE=$dh_size ./easyrsa gen-dh >/dev/null 2>>"$err_file" || exit 1
      
      ./easyrsa build-server-full server nopass >/dev/null 2>>"$err_file" || exit 1
      openvpn --genkey --secret /etc/openvpn/ta.key >/dev/null 2>>"$err_file" || exit 1
      
      # Server config
      cat << EOF > /etc/openvpn/server.conf
port 1194
proto udp
dev tun
ca easy-rsa/pki/ca.crt
cert easy-rsa/pki/issued/server.crt
key easy-rsa/pki/private/server.key
dh easy-rsa/pki/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
keepalive 10 120
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF

      # Enable and start with retry
      systemctl enable openvpn@server >/dev/null 2>>"$err_file" || exit 1
      if ! systemctl start openvpn@server >/dev/null 2>>"$err_file"; then
          systemctl restart openvpn@server >/dev/null 2>>"$err_file" || exit 1
      fi ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    rm -f "$err_file"
    [ $exit_status -ne 0 ] && log_error "OpenVPN failed."
    
    # Generate client cert
    cd /etc/openvpn/easy-rsa || log_error "Easy-RSA directory missing after installation."
    EASYRSA_BATCH=1 ./easyrsa build-client-full client nopass >/dev/null 2>>"$LOG_FILE" || log_error "OpenVPN client certificate generation failed."
    log_info "Client cert generated: /etc/openvpn/easy-rsa/pki/issued/client.crt"
    echo "Export client files via: scp root@server:/etc/openvpn/easy-rsa/pki/{ca.crt,client.crt,client.key,issued/client.crt} /local/path"
    
    log_info "OpenVPN installed. Change passwords/keys!"
}

uninstall_openvpn() {
    systemctl stop openvpn@server 2>/dev/null || true
    $REMOVE_CMD openvpn easy-rsa
    rm -rf /etc/openvpn
    log_info "OpenVPN uninstalled."
}

show_openvpn_instructions() {
    log_info "OpenVPN Instructions: scp ca.crt client.crt client.key ta.key from server; use openvpn --config client.ovpn"
}

# Install WireGuard
install_wireguard() {
    backup_configs
    log_info "Installing WireGuard..."
    printf "Installing... "
    local err_file=$(mktemp)
    ( $INSTALL_CMD wireguard-tools >/dev/null 2>"$err_file" || exit 1
      mkdir -p /etc/wireguard
      wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key >/dev/null 2>>"$err_file" || exit 1
      chmod 600 /etc/wireguard/private.key
      
      cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
PrivateKey = $(cat /etc/wireguard/private.key)
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

      sysctl -w net.ipv4.ip_forward=1 >>"$err_file" 2>&1 || exit 1
      echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
      
      wg-quick up wg0 >/dev/null 2>>"$err_file" || exit 1
      systemctl enable wg-quick@wg0 >/dev/null 2>>"$err_file" || exit 1 ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    rm -f "$err_file"
    [ $exit_status -ne 0 ] && log_error "WireGuard failed."
    log_info "WireGuard installed. Rotate keys regularly."
}

uninstall_wireguard() {
    wg-quick down wg0 2>/dev/null || true
    $REMOVE_CMD wireguard-tools
    rm -rf /etc/wireguard
    log_info "WireGuard uninstalled."
}

show_wireguard_instructions() {
    log_info "WireGuard Instructions: Generate client keys, add peer to server wg0.conf, wg-quick up wg-client."
}

# Install SoftEther (auto-download)
install_softether() {
    backup_configs
    log_info "Installing SoftEther..."
    printf "Downloading and installing... "
    local err_file=$(mktemp)
    ( $INSTALL_CMD build-essential >/dev/null 2>"$err_file" || exit 1  # Prerequisites
      cd /tmp
      wget --no-check-certificate https://www.softether-download.com/files/softether/v4.41-978-beta/softether-vpnserver-v4.41-978-beta-2023.08.31-linux-x64-64bit.tar.gz -O softether.tar.gz >/dev/null 2>>"$err_file" || exit 1  # Latest as of 2025 search
      tar xzf softether.tar.gz >/dev/null 2>>"$err_file" || exit 1
      cd vpnserver >/dev/null 2>>"$err_file" || exit 1
      make >/dev/null 2>>"$err_file" || exit 1
      mkdir /usr/local/vpnserver >/dev/null 2>>"$err_file" || exit 1
      cp * /usr/local/vpnserver/ >/dev/null 2>>"$err_file" || exit 1
      cd /usr/local/vpnserver
      chmod 755 vpnserver vpncmd
      ./vpnserver start >/dev/null 2>>"$err_file" || exit 1
      
      # Create service
      cat << EOF > /etc/systemd/system/vpnserver.service
[Unit]
Description=SoftEther VPN Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/vpnserver/vpnserver start
ExecStop=/usr/local/vpnserver/vpnserver stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload >/dev/null 2>>"$err_file" || exit 1
      systemctl enable vpnserver >/dev/null 2>>"$err_file" || exit 1
      systemctl start vpnserver >/dev/null 2>>"$err_file" || exit 1 ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    rm -f "$err_file"
    [ $exit_status -ne 0 ] && log_error "SoftEther failed."
    log_info "SoftEther installed. Change default password: vpncmd /SERVER localhost /PASSWORD:adminpassword /CMD ServerPasswordSet"
}

uninstall_softether() {
    systemctl stop vpnserver 2>/dev/null || true
    rm -rf /usr/local/vpnserver
    rm /etc/systemd/system/vpnserver.service
    systemctl daemon-reload
    log_info "SoftEther uninstalled."
}

show_softether_instructions() {
    log_info "SoftEther Instructions:"
    log_info "- Download SoftEther VPN Client Manager from softether.org"
    log_info "- Server: <your-server-ip>:443 (or 992 for TCP)"
    log_info "- Hub: DEFAULT"
    log_info "- Auth: Use vpncmd to create users: vpncmd /SERVER localhost:5555 /PASSWORD <serverpass> /HUB:DEFAULT /CMD UserCreate user1 /REALNAME:user1 /CMD UserPasswordSet user1 /PASSWORD:pass123"
    log_info "- Enable L2TP/IPsec or OpenVPN in SoftEther for compatibility."
    log_info "Default port for management: 5555, but use client for connections."
}

# Network Config
setup_network_config() {
    log_info "Setting up network for CCDC..."
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >> $LOG_FILE 2>&1 || log_warn "IP forward failed."
    
    # Detect external interface
    local ext_interface=$(ip route | grep default | awk '{print $5}' | head -1 || echo "eth0")
    
    # Firewall (with duplicate check)
    if command -v ufw &> /dev/null; then
        ufw --force enable >> $LOG_FILE 2>&1 || true
        ufw allow 22/tcp >> $LOG_FILE 2>&1 || true
        ufw allow 1194/udp >> $LOG_FILE 2>&1 || true
        ufw allow 51820/udp >> $LOG_FILE 2>&1 || true
        ufw allow 443/tcp >> $LOG_FILE 2>&1 || true
        ufw reload >> $LOG_FILE 2>&1 || true
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=openvpn >> $LOG_FILE 2>&1 || true
        firewall-cmd --permanent --add-port=51820/udp >> $LOG_FILE 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >> $LOG_FILE 2>&1 || true
        firewall-cmd --reload >> $LOG_FILE 2>&1 || true
    else
        $INSTALL_CMD ufw >> $LOG_FILE 2>&1 || true
        # Re-run if installed
    fi
    
    # NAT with duplicate removal
    iptables -t nat -D POSTROUTING -o "$ext_interface" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i wg+ -j ACCEPT 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o "$ext_interface" -j MASQUERADE
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -i wg+ -j ACCEPT
    
    # Persist
    if command -v netfilter-persistent &> /dev/null; then netfilter-persistent save; fi
    
    log_info "Network config complete. Verify Palo Alto NAT."
}

show_active_services() {
    log_info "Showing active VPN services..."
    if is_openvpn_installed; then
        systemctl status openvpn@server || log_warn "OpenVPN not running."
    fi
    if is_wireguard_installed; then
        wg show wg0 || log_warn "WireGuard not running."
    fi
    if is_softether_installed; then
        /usr/local/vpnserver/vpncmd /SERVER localhost /CMD StatusGet || log_warn "SoftEther not running."
    fi
}

show_certificate_management() {
    log_info "Certificate & User Management"
    echo "For OpenVPN: Use easyrsa in /etc/openvpn/easy-rsa to build/revoke clients."
    echo "For WireGuard: Generate keys and add [Peer] to wg0.conf."
    echo "For SoftEther: Use vpncmd to manage users/hubs."
}

run_vpn_diagnostics() {
    log_info "Running VPN Diagnostics..."
    log_info "PBF Moderate: IDS-like port checks performed."
    echo "Checking open ports..."
    if command -v netstat &> /dev/null; then
        netstat -tuln
    else
        ss -tuln
    fi
    show_active_services
}

show_integration_help() {
    log_info "Integration & Testing Help"
    echo "For CCDC: Ensure firewalls allow VPN ports, test connections from external."
    echo "Integrate with Palo Alto NAT if needed."
    echo "Test multi-device connectivity."
}

# Security warnings enhanced
check_security_warnings() {
    log_info "SECURITY AUDIT..."
    # Enhanced: Prompt for changes
    if is_softether_installed; then
        read -p "Change SoftEther password? (y/n): " change_pw
        [ "$change_pw" = "y" ] && /usr/local/vpnserver/vpncmd /SERVER localhost /PASSWORD:adminpassword /CMD ServerPasswordSet
    fi
    # ... (original)
}

# Main
main() {
    check_root
    detect_pkg_manager
    fix_dpkg
    echo "VPN Installer started: $(date)" | tee -a $LOG_FILE
    update_system
    install_dependencies
    setup_network_config
    check_security_warnings
    if [ ${#VPN_FLAGS[@]} -gt 0 ]; then
        install_mode  # Use flags
    else
        prompt_mode
    fi
    log_info "Script complete. Check log and change defaults!"
}

main "$@"