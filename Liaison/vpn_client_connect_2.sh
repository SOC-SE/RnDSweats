#!/bin/bash

# Test comment added by agent mode for vpn_client_connect_2.sh

set -euo pipefail

# ==============================================================================
# File: vpn_client_connect_2.sh
# Description: VPN Client Connection Manager for connecting to remote VPN servers.
#              Supports connecting to OpenVPN, WireGuard, and SoftEther VPN servers.
#              Menu-driven interface for easy VPN client setup and connection.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS/RHEL (dnf).
#              Guides users through entering server details and establishing connections.
#              Includes connection testing and troubleshooting tips. Added file transfer.
#
# Dependencies: apt (Debian/Ubuntu) or dnf (Fedora/CentOS/RHEL).
# Usage: sudo ./vpn_client_connect_2.sh
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
log_info() { echo -e "${GREEN}[INFO] $1${NC}" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2 | tee -a "$LOG_FILE"; exit 1; }
log_step() { echo -e "${BLUE}[STEP] $1${NC}"; }

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root for interface management (or use sudo for wg-quick/openvpn)."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt install -y"
        UPDATE_CMD="apt update -y"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
    else
        log_error "Unsupported package manager (apt or dnf)."
    fi
    log_info "Detected: $PKG_MANAGER"
}

# Install nc if missing (cross-distro)
install_nc() {
    if ! command -v nc >/dev/null 2>&1; then
        log_info "Installing netcat..."
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            $INSTALL_CMD netcat-openbsd >> "$LOG_FILE" 2>&1 || log_warn "nc install failed."
        else  # dnf
            $INSTALL_CMD nc >> "$LOG_FILE" 2>&1 || log_warn "nc install failed."
        fi
        command -v nc >/dev/null 2>&1 || log_warn "nc still unavailable; UDP tests limited."
    fi
}

# --- Update System ---
update_system() {
    log_info "Updating packages..."
    $UPDATE_CMD >> "$LOG_FILE" 2>&1 || log_warn "Update check failed, continuing."
}

# --- Validate IP Address (made ipcalc optional) ---
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then return 1; fi
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]] || return 1
    # Optional ipcalc for extra validation
    if command -v ipcalc >/dev/null 2>&1; then
        ipcalc "$ip" >/dev/null 2>&1 || return 1
    fi
    return 0
}

# --- Test Server Connectivity (fixed UDP with nc -u) ---
test_connectivity() {
    local server_ip=$1 port=$2 protocol=${3:-tcp}
    install_nc  # Ensure nc available
    log_info "Testing $server_ip:$port ($protocol)..."
    local timeout_val=10  # Increased from 5s
    if [ "$protocol" = "udp" ]; then
        nc -u -z -w "$timeout_val" "$server_ip" "$port" 2>/dev/null && log_info "UDP passed" || log_warn "UDP failed (firewall/port issue?)."
    else
        nc -z -w "$timeout_val" "$server_ip" "$port" 2>/dev/null && log_info "TCP passed" || log_warn "TCP failed (firewall/port issue?)."
    fi
}

# --- Detect Server VPNs (fixed UDP tests) ---
detect_server_vpns() {
    local server_ip=$1
    log_info "Detecting services on $server_ip..."
    local available_vpns=()
    test_connectivity "$server_ip" 1194 "udp" && available_vpns+=("OpenVPN (UDP:1194)")
    test_connectivity "$server_ip" 51820 "udp" && available_vpns+=("WireGuard (UDP:51820)")
    test_connectivity "$server_ip" 443 "tcp" && available_vpns+=("SoftEther (TCP:443)")
    test_connectivity "$server_ip" 992 "tcp" && available_vpns+=("SoftEther Alt (TCP:992)")
    if [ ${#available_vpns[@]} -eq 0 ]; then
        log_warn "No VPN services detected. Check firewall or server status."
        return 1
    fi
    for vpn in "${available_vpns[@]}"; do echo "  - $vpn"; done
    return 0
}

# --- Configuration Validation (improved) ---
validate_vpn_config() {
    local vpn_type=$1 server_ip=$2 port=$3 protocol=${4:-"auto"}
    log_info "Validating $vpn_type config for $server_ip:$port..."
    local proto_to_use
    case "$vpn_type" in
        "openvpn") proto_to_use="udp" ;;
        "wireguard") proto_to_use="udp" ;;
        "softether") proto_to_use="tcp" ;;
        *) proto_to_use="$protocol" ;;
    esac
    if [ "$protocol" = "auto" ]; then
        proto_to_use="$proto_to_use"
    fi
    test_connectivity "$server_ip" "$port" "$proto_to_use"
    # Additional: Quick resolve test
    getent hosts "$server_ip" >/dev/null 2>&1 || log_warn "IP resolution failed (DNS?)."
}

# --- OpenVPN Client Setup (fixed config test, file checks, modern cipher) ---
setup_openvpn_client() {
    log_step "OpenVPN Setup"
    $INSTALL_CMD openvpn >> "$LOG_FILE" 2>&1 || log_error "OpenVPN install failed."
    read -p "Server IP: " SERVER_IP
    validate_ip "$SERVER_IP" || log_error "Invalid IP."
    read -p "Port (default 1194): " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-1194}
    read -p "Protocol (udp/tcp) [udp]: " PROTOCOL; PROTOCOL=${PROTOCOL:-udp}
    validate_vpn_config "openvpn" "$SERVER_IP" "$SERVER_PORT" "$PROTOCOL"
    
    read -p "CA cert path: " CA_CERT
    read -p "Client cert path: " CLIENT_CERT
    read -p "Client key path: " CLIENT_KEY
    read -p "TA key path [optional, enter for none]: " TA_KEY
    
    for file in "$CA_CERT" "$CLIENT_CERT" "$CLIENT_KEY"; do 
        [ -f "$file" ] || log_error "File missing: $file (provide full path)."
    done
    [ -n "$TA_KEY" ] && [ ! -f "$TA_KEY" ] && log_error "TA key file missing: $TA_KEY"
    
    local CLIENT_CONFIG="/etc/openvpn/client.conf"
    cat > "$CLIENT_CONFIG" << EOF
client
proto $PROTOCOL
remote $SERVER_IP $SERVER_PORT
resolv-retry infinite
nobind
dev tun
ca $CA_CERT
cert $CLIENT_CERT
key $CLIENT_KEY
EOF
    if [ -n "$TA_KEY" ] && [ -f "$TA_KEY" ]; then 
        echo "tls-auth $TA_KEY 1" >> "$CLIENT_CONFIG"
    fi
    cat >> "$CLIENT_CONFIG" << EOF
cipher AES-256-GCM
auth SHA256
verb 3
EOF

    log_info "Config created at $CLIENT_CONFIG."
    # Syntax-only test (no startup)
    if ! openvpn --config "$CLIENT_CONFIG" --test 2>&1 | head -5 | grep -q "Initialization Sequence Completed"; then
        log_warn "Config syntax check: Potential issues detected (full log in $LOG_FILE)."
    else
        log_info "Config syntax valid."
    fi
    
    log_step "Connect: sudo openvpn --config $CLIENT_CONFIG"
    echo "Disconnect: sudo pkill openvpn"
    echo "Status: ip addr show tun0; ping 10.8.0.1  # Assuming server subnet"
    log_warn "For production: Add auth-user-pass if username/password auth enabled."
}

# --- WireGuard Client Setup (added DNS/keepalive, IP prompt) ---
setup_wireguard_client() {
    log_step "WireGuard Setup"
    $INSTALL_CMD wireguard-tools >> "$LOG_FILE" 2>&1 || log_error "WireGuard install failed."
    log_info "Generating client keys..."
    mkdir -p /etc/wireguard
    wg genkey | tee /etc/wireguard/client_private.key | wg pubkey > /etc/wireguard/client_public.key || log_error "Key gen failed."
    chmod 600 /etc/wireguard/client_private.key
    local CLIENT_PRIVATE_KEY=$(cat /etc/wireguard/client_private.key)
    local CLIENT_PUBLIC_KEY=$(cat /etc/wireguard/client_public.key)
    
    echo "Client pubkey: $CLIENT_PUBLIC_KEY (share securely with server admin)"
    read -p "Client IP (e.g., 10.0.0.2/24, default 10.0.0.2/24): " CLIENT_IP; CLIENT_IP=${CLIENT_IP:-10.0.0.2/24}
    read -p "Server IP: " SERVER_IP
    validate_ip "$SERVER_IP" || log_error "Invalid server IP."
    read -p "Port (default 51820): " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-51820}
    read -p "Server pubkey: " SERVER_PUBLIC_KEY
    if [[ -z "$SERVER_PUBLIC_KEY" ]]; then log_error "Server pubkey required."; fi
    validate_vpn_config "wireguard" "$SERVER_IP" "$SERVER_PORT"
    
    local CLIENT_CONFIG="/etc/wireguard/wg-client.conf"
    cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 8.8.8.8  # Google DNS, change if needed

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    log_step "On server: Add [Peer] to wg0.conf: PublicKey=$CLIENT_PUBLIC_KEY AllowedIPs=${CLIENT_IP%/24}/32"
    log_step "Server restart: sudo wg-quick down wg0; sudo wg-quick up wg0"
    log_step "Connect: sudo wg-quick up $CLIENT_CONFIG"
    echo "Status: wg show; ping 10.0.0.1  # Assuming server IP"
    echo "Disconnect: sudo wg-quick down wg-client"
    log_warn "SECURITY: Never share private key. For multiple clients, increment IP."
}

# --- SoftEther Client Setup (added L2TP notes) ---
setup_softether_client() {
    log_step "SoftEther Setup"
    log_info "Download SoftEther VPN Client: https://www.softether.org/5-download (or use L2TP/IPsec for built-in)."
    read -p "Client installed and ready? (y/n): " INSTALLED
    [[ "$INSTALLED" =~ ^[yY]$ ]] || { log_warn "Install client first."; return; }
    
    read -p "Server IP: " SERVER_IP
    validate_ip "$SERVER_IP" || log_error "Invalid IP."
    read -p "Port (default 443): " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-443}
    read -p "Virtual Hub (default DEFAULT or SEHUB): " HUB_NAME; HUB_NAME=${HUB_NAME:-DEFAULT}
    validate_vpn_config "softether" "$SERVER_IP" "$SERVER_PORT"
    
    log_step "GUI Connection Settings:"
    echo "  - Host: $SERVER_IP"
    echo "  - Port: $SERVER_PORT"
    echo "  - Virtual Hub: $HUB_NAME"
    echo "  - Auth Type: Standard Password (or RADIUS/Certificate)"
    echo "  - Username/Password: From server admin (default may be 'testuser/password' – change it!)"
    log_step "Server-side User Creation (run on server):"
    echo "  /usr/local/vpnserver/vpncmd /SERVER localhost /PASSWORD:<serverpass> /HUB:$HUB_NAME /CMD UserCreate <username> /CMD UserPasswordSet <username> <password>"
    log_step "L2TP/IPsec Alternative (no GUI needed):"
    echo "  - PSK: From server (default 'vpn')"
    echo "  - On client: Network settings -> VPN -> Add L2TP, Server: $SERVER_IP, PSK: vpn, User/Pass from server"
    log_warn "Test: Connect and ping server tunnel IP (e.g., 192.168.30.1 for default hub)."
}

# --- File Transfer Module (fixed prompts, checks) ---
file_transfer_menu() {
    log_step "File Transfer over VPN (SCP/RSYNC)"
    # Quick VPN check
    if ! ip link show | grep -qE "(tun|wg)[0-9]+"; then
        read -p "VPN interface active? (run 'ip link show' to check, y/n): " connected
        [[ "$connected" =~ ^[yY]$ ]] || { log_warn "Connect VPN first (e.g., wg-quick up)."; return; }
    fi
    echo "1) Send file to remote (scp)"
    echo "2) Receive file from remote (scp)"
    echo "3) Sync directory to remote (rsync)"
    read -p "Choice (1-3, or q to quit): " ft_choice
    case "$ft_choice" in
        1|2|3) ;;
        q|Q) return ;;
        *) log_warn "Invalid choice."; return ;;
    esac
    read -p "Remote host (user@VPN-IP, e.g., root@10.0.0.1): " remote
    [[ -n "$remote" ]] || log_error "Remote host required."
    case $ft_choice in
        1)
            read -p "Local file/path to send: " local_file
            read -p "Remote destination (e.g., /home/user/file.txt): " remote_dest
            scp "$local_file" "$remote:$remote_dest" || log_error "SCP send failed (check SSH keys?)."
            ;;
        2)
            read -p "Remote file/path to receive: " remote_path
            read -p "Local destination (e.g., /home/user/file.txt): " local_dest
            scp "$remote:$remote_path" "$local_dest" || log_error "SCP receive failed."
            ;;
        3)
            read -p "Local directory to sync: " local_dir
            read -p "Remote directory (e.g., /home/user/dir): " remote_dir
            rsync -avz -e ssh "$local_dir/" "$remote:$remote_dir" || log_error "RSYNC failed."
            ;;
    esac
    log_info "Transfer complete. PBF Core: Clean temp files: rm -rf /tmp/vpn_*"
    log_warn "Ensure SSH is enabled on remote and keys are set (ssh-keygen; ssh-copy-id)."
}

# --- Main Menu (added input validation) ---
show_menu() {
    echo ""
    log_info "VPN Client Manager Menu"
    echo "1) OpenVPN Client Setup"
    echo "2) WireGuard Client Setup"
    echo "3) SoftEther Client Setup"
    echo "4) Detect VPN Services on Server"
    echo "5) Test Server Connectivity"
    echo "6) File Transfer over VPN"
    echo "7) Exit"
    read -p "Option (1-7): " choice
    case "${choice:-0}" in  # Default to invalid
        1) setup_openvpn_client ;;
        2) setup_wireguard_client ;;
        3) setup_softether_client ;;
        4) 
            read -p "Server IP to scan: " SCAN_IP
            if validate_ip "$SCAN_IP"; then
                detect_server_vpns "$SCAN_IP"
            else
                log_error "Invalid IP for scan."
            fi
            ;;
        5) 
            read -p "Server IP: " TEST_IP
            read -p "Port (default 443): " TEST_PORT; TEST_PORT=${TEST_PORT:-443}
            read -p "Protocol (tcp/udp) [tcp]: " TEST_PROTO; TEST_PROTO=${TEST_PROTO:-tcp}
            if validate_ip "$TEST_IP"; then
                test_connectivity "$TEST_IP" "$TEST_PORT" "$TEST_PROTO"
            else
                log_error "Invalid IP."
            fi
            ;;
        6) file_transfer_menu ;;
        7) log_info "Exiting."; exit 0 ;;
        *) log_warn "Invalid option. Try 1-7." ;;
    esac
}

# --- Main Logic (fixed loop, conditional cleanup) ---
main() {
    check_root
    detect_pkg_manager
    update_system
    install_nc
    echo "VPN Client Manager started: $(date)" | tee -a "$LOG_FILE"
    while true; do
        show_menu
        read -p "Return to main menu? (y/n) [y]: " CONTINUE; CONTINUE=${CONTINUE:-y}
        [[ "$CONTINUE" =~ ^[nN]$ ]] && break
    done
    # Conditional cleanup (only if WireGuard setup run)
    if [[ -f /etc/wireguard/client_private.key ]]; then
        rm -f /etc/wireguard/client_private.key /etc/wireguard/client_public.key 2>/dev/null || true
        log_info "WireGuard client keys cleaned up."
    fi
    log_info "Session complete. Logs in $LOG_FILE"
}

main "$@"
