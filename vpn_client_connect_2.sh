#!/bin/bash

set -euo pipefail

# ==============================================================================
# File: vpn_client_connect.sh
# Description: VPN Client Connection Manager for connecting to remote VPN servers.
#              Supports connecting to OpenVPN, WireGuard, and SoftEther VPN servers.
#              Menu-driven interface for easy VPN client setup and connection.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS/RHEL (dnf).
#              Guides users through entering server details and establishing connections.
#              Includes connection testing and troubleshooting tips. Added file transfer.
#
# Dependencies: apt (Debian/Ubuntu) or dnf (Fedora/CentOS/RHEL).
# Usage: sudo ./vpn_client_connect.sh
# Notes:
# - Run as root for VPN interface management.
# - Ensure server information is correct before connecting.
# - For CCDC: Verify firewall rules allow VPN traffic.
# - Test connections in a safe environment first.
# ==============================================================================

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
__     ______  _   _    ____                            _   _ 
\ \   / /  _ \| \ | |  / ___|___  _ __  _ __   ___  ___| |_| |
 \ \ / /| |_) |  \| | | |   / _ \| '_ \| '_ \ / _ \/ __| __| |
  \ V / |  __/| |\  | | |__| (_) | | | | | | |  __/ (__| |_|_|
   \_/  |_|   |_| \_|  \____\___/|_| |_|_| |_|\___|\___|\__(_)
EOF
echo -e "\033[0m"
echo "VPN Client Connection Manager"
echo "----------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
LOG_FILE="/var/log/vpn_client.log"

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}" | tee -a $LOG_FILE; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}" | tee -a $LOG_FILE; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2 | tee -a $LOG_FILE; exit 1; }
log_step() { echo -e "${BLUE}[STEP] $1${NC}"; }

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt install -y"
        UPDATE_CMD="apt update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
    else
        log_error "Unsupported package manager."
    fi
    log_info "Detected: $PKG_MANAGER"
}

# Install nc if missing
install_nc() {
    if ! command -v nc &> /dev/null; then
        log_info "Installing netcat..."
        $INSTALL_CMD netcat-openbsd >> $LOG_FILE 2>&1 || log_warn "nc install failed."
    fi
}

# --- Update System ---
update_system() {
    log_info "Updating packages..."
    $UPDATE_CMD >> $LOG_FILE 2>&1 || log_warn "Update failed."
}

# --- Validate IP Address (improved) ---
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then return 1; fi
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    [ $a -le 255 ] && [ $b -le 255 ] && [ $c -le 255 ] && [ $d -le 255 ] || return 1
    command -v ipcalc &> /dev/null && ipcalc "$ip" &> /dev/null || return 1
    return 0
}

# --- Test Server Connectivity ---
test_connectivity() {
    local server_ip=$1 port=$2 protocol=${3:-tcp}
    install_nc  # Ensure nc available
    log_info "Testing $server_ip:$port ($protocol)..."
    if [ "$protocol" = "udp" ]; then
        timeout 5 bash -c "echo > /dev/udp/$server_ip/$port" 2>/dev/null && log_info "UDP passed" || log_warn "UDP failed."
    else
        nc -z -w5 "$server_ip" "$port" 2>/dev/null && log_info "TCP passed" || log_warn "TCP failed."
    fi
}

# --- Detect Server VPNs ---
detect_server_vpns() {
    local server_ip=$1
    log_info "Detecting on $server_ip..."
    local available_vpns=()
    timeout 5 bash -c "echo > /dev/udp/$server_ip/1194" 2>/dev/null && available_vpns+=("OpenVPN (UDP:1194)")
    timeout 5 bash -c "echo > /dev/udp/$server_ip/51820" 2>/dev/null && available_vpns+=("WireGuard (UDP:51820)")
    nc -z -w3 "$server_ip" 443 2>/dev/null && available_vpns+=("SoftEther (TCP:443)")
    if [ ${#available_vpns[@]} -eq 0 ]; then
        log_warn "No services detected."
        return 1
    fi
    for vpn in "${available_vpns[@]}"; do echo "  - $vpn"; done
    return 0
}

# --- Configuration Validation ---
validate_vpn_config() {
    local vpn_type=$1 server_ip=$2 port=$3 protocol=${4:-"auto"}
    log_info "Validating $vpn_type..."
    # ... (original validation logic)
    if [ "$protocol" = "auto" ]; then
        case $vpn_type in "openvpn") test_connectivity "$server_ip" "$port" "udp" ;; "wireguard") test_connectivity "$server_ip" "$port" "udp" ;; "softether") test_connectivity "$server_ip" "$port" "tcp" ;; esac
    else
        test_connectivity "$server_ip" "$port" "$protocol"
    fi
}

# --- OpenVPN Client Setup ---
setup_openvpn_client() {
    log_step "OpenVPN Setup"
    $INSTALL_CMD openvpn >> $LOG_FILE 2>&1 || log_error "OpenVPN install failed."
    read -p "Server IP: " SERVER_IP
    validate_ip "$SERVER_IP" || log_error "Invalid IP."
    read -p "Port (default 1194): " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-1194}
    read -p "Protocol (udp/tcp) [udp]: " PROTOCOL; PROTOCOL=${PROTOCOL:-udp}
    validate_vpn_config "openvpn" "$SERVER_IP" "$SERVER_PORT" "$PROTOCOL"
    
    read -p "CA cert path: " CA_CERT
    read -p "Client cert path: " CLIENT_CERT
    read -p "Client key path: " CLIENT_KEY
    read -p "TA key path [optional]: " TA_KEY
    
    for file in "$CA_CERT" "$CLIENT_CERT" "$CLIENT_KEY"; do [ -f "$file" ] || log_error "File missing: $file"; done
    
    local CLIENT_CONFIG="/etc/openvpn/client.conf"
    cat > "$CLIENT_CONFIG" << EOF
client
proto $PROTOCOL
remote $SERVER_IP $SERVER_PORT
dev tun
ca $CA_CERT
cert $CLIENT_CERT
key $CLIENT_KEY
EOF
    [ -n "$TA_KEY" ] && [ -f "$TA_KEY" ] && echo "tls-auth $TA_KEY 1" >> "$CLIENT_CONFIG"
    cat >> "$CLIENT_CONFIG" << EOF
cipher AES-256-CBC
verb 3
EOF

    log_info "Config created."
    # Fixed test
    if openvpn --config "$CLIENT_CONFIG" --verb 0 2>&1 | head -1 | grep -q "Options error"; then
        log_warn "Config syntax issues."
    else
        log_info "Config valid."
    fi
    
    log_step "Connect: sudo openvpn --config $CLIENT_CONFIG"
    echo "Disconnect: sudo killall openvpn"
    echo "Status: ip addr show tun0; ping 10.8.0.1"
}

# --- WireGuard Client Setup ---
setup_wireguard_client() {
    log_step "WireGuard Setup"
    $INSTALL_CMD wireguard-tools >> $LOG_FILE 2>&1 || log_error "WireGuard install failed."
    log_info "Generating keys..."
    mkdir -p /etc/wireguard
    wg genkey | tee /etc/wireguard/client_private.key | wg pubkey > /etc/wireguard/client_public.key
    chmod 600 /etc/wireguard/client_private.key
    local CLIENT_PRIVATE_KEY=$(cat /etc/wireguard/client_private.key)
    local CLIENT_PUBLIC_KEY=$(cat /etc/wireguard/client_public.key)
    
    echo "Client pubkey: $CLIENT_PUBLIC_KEY (share with server)"
    read -p "Server IP: " SERVER_IP
    validate_ip "$SERVER_IP" || log_error "Invalid IP."
    read -p "Port (default 51820): " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-51820}
    read -p "Server pubkey: " SERVER_PUBLIC_KEY
    validate_vpn_config "wireguard" "$SERVER_IP" "$SERVER_PORT" "udp"
    
    local CLIENT_CONFIG="/etc/wireguard/wg-client.conf"
    cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
EOF

    log_step "Add to server: [Peer] PublicKey=$CLIENT_PUBLIC_KEY AllowedIPs=10.0.0.2/32; wg-quick down/up wg0"
    log_step "Connect: sudo wg-quick up wg-client"
    echo "Status: wg show; ping 10.0.0.1"
    echo "Disconnect: sudo wg-quick down wg-client"
}

# --- SoftEther Client Setup ---
setup_softether_client() {
    log_step "SoftEther Setup"
    log_info "SoftEther client: Download from https://www.softether.org/"
    read -p "Installed? (y/n): " INSTALLED
    [ "$INSTALLED" != "y" ] && [ "$INSTALLED" != "Y" ] && return
    
    read -p "Server IP: " SERVER_IP
    validate_ip "$SERVER_IP" || log_error "Invalid IP."
    read -p "Port (default 443): " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-443}
    read -p "Hub (default SEHUB): " HUB_NAME; HUB_NAME=${HUB_NAME:-SEHUB}
    validate_vpn_config "softether" "$SERVER_IP" "$SERVER_PORT" "tcp"
    
    log_step "GUI Settings: Host=$SERVER_IP, Port=$SERVER_PORT, Hub=$HUB_NAME, Auth=Standard, User/Pass from server"
    log_step "Server user create: vpncmd /SERVER localhost /PASSWORD:adminpassword /HUB:$HUB_NAME /CMD UserCreate user /CMD UserPasswordSet user"
}

# --- File Transfer Module (New) ---
file_transfer_menu() {
    log_step "File Transfer over VPN"
    read -p "VPN connected? (y/n): " connected
    [ "$connected" != "y" ] && log_warn "Connect VPN first." && return
    echo "1) Send file (scp)"
    echo "2) Receive file (scp)"
    echo "3) Sync dir (rsync)"
    read -p "Choice (1-3): " ft_choice
    read -p "Remote user@VPN-IP: " remote
    case $ft_choice in
        1) read -p "Local file: " local_file; scp "$local_file" "$remote:/path" ;;
        2) read -p "Remote file/path: " remote_path; scp "$remote:$remote_path" /local/path ;;
        3) read -p "Local dir: " local_dir; read -p "Remote dir: " remote_dir; rsync -avz -e ssh "$local_dir" "$remote:$remote_dir" ;;
    esac
    log_info "PBF Core: Prune temp files after transfer: rm -rf /tmp/*"
}

# --- Main Menu ---
show_menu() {
    echo ""
    log_info "VPN Client Manager"
    echo "1) OpenVPN"
    echo "2) WireGuard"
    echo "3) SoftEther"
    echo "4) Detect Services"
    echo "5) Test Connectivity"
    echo "6) File Transfer (over VPN)"
    echo "7) Exit"
    read -p "Option (1-7): " choice
    case $choice in
        1) setup_openvpn_client ;;
        2) setup_wireguard_client ;;
        3) setup_softether_client ;;
        4) read -p "Server IP: " SCAN_IP; validate_ip "$SCAN_IP" && detect_server_vpns "$SCAN_IP" || log_error "Invalid IP." ;;
        5) read -p "Server IP: " TEST_IP; read -p "Port: " TEST_PORT; read -p "Protocol [tcp]: " TEST_PROTO; TEST_PROTO=${TEST_PROTO:-tcp}; test_connectivity "$TEST_IP" "$TEST_PORT" "$TEST_PROTO" ;;
        6) file_transfer_menu ;;
        7) log_info "Exiting."; exit 0 ;;
        *) log_warn "Invalid." ;;
    esac
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    update_system
    install_nc
    echo "Started: $(date)" | tee -a $LOG_FILE
    while true; do
        show_menu
        read -p "Main menu? (y/n): " CONTINUE
        [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ] && break
    done
    # Cleanup
    rm -f /etc/wireguard/client_private.key 2>/dev/null || true
    log_info "Session complete."
}

main "$@"