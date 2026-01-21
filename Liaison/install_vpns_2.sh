#!/bin/bash

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

set -euo pipefail

# --- Styling & Logging -------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

LOG_ROOT="${VPN_NEXUS_LOG_DIR:-/var/log/vpn_nexus}"
LOG_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if ! mkdir -p "$LOG_ROOT" 2>/dev/null; then
    LOG_ROOT="/tmp/vpn_nexus"
    mkdir -p "$LOG_ROOT"
fi
LOG_FILE="${LOG_ROOT}/install_${LOG_TIMESTAMP}.log"
if ! touch "$LOG_FILE" 2>/dev/null; then
    LOG_FILE="/tmp/vpn_installer_${LOG_TIMESTAMP}.log"
    touch "$LOG_FILE" 2>/dev/null || echo "" > "$LOG_FILE"
fi

log_info() {
    printf '%b[INFO]%b %s\n' "$GREEN" "$RESET" "$1"
    printf '[INFO] %s\n' "$1" >> "$LOG_FILE"
}

log_warn() {
    printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$1"
    printf '[WARN] %s\n' "$1" >> "$LOG_FILE"
}

log_error() {
    printf '%b[ERROR]%b %s\n' "$RED" "$RESET" "$1" >&2
    printf '[ERROR] %s\n' "$1" >> "$LOG_FILE"
    exit 1
}

spinner() {
    local pid=$1
    local spin='|/-\\'
    local delay=0.15
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r%b[%c] Working...%b' "$YELLOW" "${spin:i%4:1}" "$RESET"
        sleep "$delay"
        i=$((i + 1))
    done
    printf '\r%*s\r' 40 ''
}

# --- Globals -----------------------------------------------------------------
OPENVPN_SERVICE_UNIT=""
PKG_MANAGER=""
INSTALL_CMD=""
UPDATE_CMD=""
UPGRADE_CMD=""
REMOVE_CMD=""
QUICK_MODE=false
declare -a VPN_FLAGS=()

ensure_openvpn_service_unit() {
    if [ -n "$OPENVPN_SERVICE_UNIT" ]; then
        return 0
    fi

    local output
    output=$(systemctl list-unit-files "openvpn-server@.service" 2>/dev/null || true)
    if echo "$output" | grep -q "openvpn-server@.service"; then
        OPENVPN_SERVICE_UNIT="openvpn-server@server"
        return 0
    fi

    output=$(systemctl list-unit-files "openvpn@.service" 2>/dev/null || true)
    if echo "$output" | grep -q "openvpn@.service"; then
        OPENVPN_SERVICE_UNIT="openvpn@server"
        return 0
    fi

    OPENVPN_SERVICE_UNIT="openvpn@server"
}

enable_and_start_openvpn_service() {
    local svc
    for svc in openvpn-server@server openvpn@server; do
        if systemctl enable "$svc" >/dev/null 2>&1; then
            if systemctl start "$svc" >/dev/null 2>&1 || systemctl restart "$svc" >/dev/null 2>&1; then
                OPENVPN_SERVICE_UNIT="$svc"
                return 0
            fi
        fi
    done
    return 1
}

prepare_easy_rsa_tree() {
    local target_dir="/etc/openvpn/easy-rsa"
    rm -rf "$target_dir"
    if command -v make-cadir >/dev/null 2>&1; then
        make-cadir "$target_dir" >>"$LOG_FILE" 2>&1
        return $?
    fi

    if [ -d /usr/share/easy-rsa ]; then
        mkdir -p "$target_dir"
        cp -r /usr/share/easy-rsa/* "$target_dir" >>"$LOG_FILE" 2>&1
        chown -R root:root "$target_dir"
        return 0
    fi

    log_error "Easy-RSA templates not found after package installation."
}

configure_softether_service_unit() {
    cat <<'EOF' > /etc/systemd/system/vpnserver.service
[Unit]
Description=SoftEther VPN Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/usr/local/vpnserver
ExecStart=/usr/local/vpnserver/vpnserver execsvc
ExecStop=/usr/local/vpnserver/vpnserver stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1
}

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
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
        UPGRADE_CMD="apt-get upgrade -y"
        REMOVE_CMD="apt-get purge -y"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf makecache --refresh"
        UPGRADE_CMD="dnf upgrade -y"
        REMOVE_CMD="dnf remove -y"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum makecache"
        UPGRADE_CMD="yum upgrade -y"
        REMOVE_CMD="yum remove -y"
    else
        log_error "Unsupported package manager (apt, dnf, or yum required)."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# Install dependencies including nc and ipcalc
install_dependencies() {
    log_info "Installing common dependencies..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        fix_dpkg
        export DEBIAN_FRONTEND=noninteractive
        $INSTALL_CMD curl wget git build-essential libssl-dev libreadline-dev zlib1g-dev libncurses-dev netcat-openbsd ipcalc easy-rsa >/dev/null 2>&1 || \
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
is_softether_installed() {
    [ -x /usr/local/vpnserver/vpnserver ] || return 1
    local output
    output=$(systemctl list-unit-files vpnserver.service 2>/dev/null || true)
    if echo "$output" | grep -q "vpnserver.service"; then
        return 0
    fi
    return 1
}

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

# Update system (optional, intentionally skipped for speed)
update_system() { log_info "Skipping updates for efficiency."; }

# Install OpenVPN with client gen
install_openvpn() {
    log_info "Installing OpenVPN..."
    printf "Installing OpenVPN... "
    local err_file=$(mktemp)
    local svc_hint=$(mktemp)
    (
      if [ "$PKG_MANAGER" = "apt" ]; then
          export DEBIAN_FRONTEND=noninteractive
      fi

      $INSTALL_CMD openvpn easy-rsa >/dev/null 2>"$err_file" || { echo "Package installation failed." >>"$err_file"; exit 1; }
      prepare_easy_rsa_tree || { echo "Easy-RSA setup failed." >>"$err_file"; exit 1; }

      cd /etc/openvpn/easy-rsa >/dev/null 2>>"$err_file" || exit 1
      export EASYRSA_BATCH=1
      export EASYRSA_REQ_CN="VPN-CA"
      ./easyrsa init-pki >/dev/null 2>>"$err_file" || { echo "PKI init failed." >>"$err_file"; exit 1; }
      ./easyrsa build-ca nopass >/dev/null 2>>"$err_file" || { echo "CA build failed." >>"$err_file"; exit 1; }

      local dh_size=2048
      if $QUICK_MODE; then
          dh_size=1024
          log_warn "Quick mode enabled: generating 1024-bit DH parameters (less secure)."
      fi
      EASYRSA_DH_KEY_SIZE=$dh_size ./easyrsa gen-dh >/dev/null 2>>"$err_file" || { echo "DH generation failed." >>"$err_file"; exit 1; }

      ./easyrsa build-server-full server nopass >/dev/null 2>>"$err_file" || { echo "Server certificate generation failed." >>"$err_file"; exit 1; }
      openvpn --genkey --secret /etc/openvpn/ta.key >/dev/null 2>>"$err_file" || { echo "TLS auth key generation failed." >>"$err_file"; exit 1; }

      mkdir -p /etc/openvpn/server
      cat <<'EOF' > /etc/openvpn/server/server.conf
port 1194
proto udp
dev tun
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
tls-auth /etc/openvpn/ta.key 0
explicit-exit-notify 1
EOF

      ln -sf /etc/openvpn/server/server.conf /etc/openvpn/server.conf
      chmod 600 /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/ta.key >/dev/null 2>>"$err_file" || true

      if enable_and_start_openvpn_service 2>>"$err_file"; then
          echo "$OPENVPN_SERVICE_UNIT" > "$svc_hint"
      else
          echo "OpenVPN service enable/start failed." >>"$err_file"
          exit 1
      fi
    ) &
    local pid=$!
    spinner "$pid"
    wait "$pid"
    local exit_status=$?
    local err_content=""
    [ -f "$err_file" ] && err_content=$(cat "$err_file")
    if [ -s "$svc_hint" ]; then
        OPENVPN_SERVICE_UNIT=$(cat "$svc_hint")
    else
        ensure_openvpn_service_unit
    fi
    rm -f "$err_file" "$svc_hint"
    if [ $exit_status -ne 0 ]; then
        echo ""
        echo -e "${RED}Error during OpenVPN installation:${NC}"
        echo "$err_content"
        log_error "OpenVPN installation failed."
    fi
    echo ""

    cd /etc/openvpn/easy-rsa || log_error "Easy-RSA directory missing after installation."
    EASYRSA_BATCH=1 ./easyrsa build-client-full client nopass >>"$LOG_FILE" 2>&1 || log_warn "Failed to pre-create client certificate. Generate manually as needed."

    log_info "OpenVPN installed and running (${OPENVPN_SERVICE_UNIT:-openvpn@server}). Client configs in /etc/openvpn/easy-rsa/pki/. Change certificates for production use."
    ensure_openvpn_service_unit
}

uninstall_openvpn() {
    ensure_openvpn_service_unit
    local svc
    for svc in openvpn-server@server openvpn@server; do
        systemctl stop "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
    done
    if [ "$PKG_MANAGER" = "apt" ]; then
        export DEBIAN_FRONTEND=noninteractive
    fi
    $REMOVE_CMD openvpn easy-rsa >/dev/null 2>&1 || true
    rm -rf /etc/openvpn /var/log/openvpn-status.log >/dev/null 2>&1 || true
    log_info "OpenVPN uninstalled."
}

show_openvpn_instructions() {
    log_info "OpenVPN connection steps:"
    echo "1. On the server, generate additional clients with: cd /etc/openvpn/easy-rsa && ./easyrsa build-client-full <name> nopass"
    echo "2. Copy /etc/openvpn/easy-rsa/pki/{ca.crt,issued/<name>.crt,private/<name>.key} and /etc/openvpn/ta.key to the client."
    echo "3. Create a client config referencing those files, or adapt /etc/openvpn/client-template.ovpn if you maintain one."
    echo "4. Connect using: sudo openvpn --config <client>.ovpn"
}

# Install WireGuard
install_wireguard() {
    backup_configs
    log_info "Installing WireGuard..."
    printf "Installing WireGuard... "
    local err_file=$(mktemp)
    (
      if [ "$PKG_MANAGER" = "apt" ]; then
          export DEBIAN_FRONTEND=noninteractive
          $INSTALL_CMD wireguard wireguard-tools >/dev/null 2>"$err_file" || { echo "WireGuard package install failed." >>"$err_file"; exit 1; }
      else
          $INSTALL_CMD wireguard-tools >/dev/null 2>"$err_file" || { echo "WireGuard package install failed." >>"$err_file"; exit 1; }
      fi

      mkdir -p /etc/wireguard
      wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key >/dev/null 2>>"$err_file" || { echo "Key generation failed." >>"$err_file"; exit 1; }
      chmod 600 /etc/wireguard/private.key >/dev/null 2>>"$err_file" || true

      local ext_interface=$(ip route | awk '/default/ {print $5; exit}')
      [ -n "$ext_interface" ] || ext_interface="eth0"

      cat <<EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
PrivateKey = $(cat /etc/wireguard/private.key)
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $ext_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $ext_interface -j MASQUERADE
EOF

      sysctl -w net.ipv4.ip_forward=1 >>"$err_file" 2>&1 || { echo "Failed to enable IP forwarding." >>"$err_file"; exit 1; }
      if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
          echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
      fi

      wg-quick up wg0 >/dev/null 2>>"$err_file" || { echo "Failed to bring up wg0." >>"$err_file"; exit 1; }
      systemctl enable wg-quick@wg0 >/dev/null 2>>"$err_file" || { echo "Failed to enable wg-quick@wg0." >>"$err_file"; exit 1; }
    ) &
    local pid=$!
    spinner "$pid"
    wait "$pid"
    local exit_status=$?
    rm -f "$err_file"
    [ $exit_status -ne 0 ] && log_error "WireGuard installation failed."
    log_info "WireGuard installed and running (wg0). Update /etc/wireguard/wg0.conf with peers and rotate keys regularly."
}

uninstall_wireguard() {
    systemctl disable --now wg-quick@wg0 >/dev/null 2>&1 || true
    wg-quick down wg0 >/dev/null 2>&1 || true
    if [ "$PKG_MANAGER" = "apt" ]; then
        export DEBIAN_FRONTEND=noninteractive
        $REMOVE_CMD wireguard wireguard-tools >/dev/null 2>&1 || true
    else
        $REMOVE_CMD wireguard-tools >/dev/null 2>&1 || true
    fi
    rm -rf /etc/wireguard >/dev/null 2>&1 || true
    log_info "WireGuard uninstalled."
}

show_wireguard_instructions() {
    log_info "WireGuard Instructions: Generate client keys, add peer to server wg0.conf, wg-quick up wg-client."
}

# Install SoftEther (auto-download)
install_softether() {
    backup_configs
    log_info "Installing SoftEther..."
    printf "Downloading and installing SoftEther... "
    local err_file
    err_file=$(mktemp)
    (
        set -e
        local softether_url="https://www.softether-download.com/files/softether/v4.43-9799-beta-2024.04.17-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-v4.43-9799-beta-2024.04.17-linux-x64-64bit.tar.gz"
        local archive="/tmp/softether.tar.gz"

        rm -rf /tmp/vpnserver
        cd /tmp || exit 1
        wget --no-check-certificate "$softether_url" -O "$archive"
        tar xzf "$archive"
        cd vpnserver || exit 1
        printf '1\n1\n1\n' | make

        mkdir -p /usr/local/vpnserver
        cp -r * /usr/local/vpnserver/
        chmod 755 /usr/local/vpnserver/vpnserver /usr/local/vpnserver/vpncmd

        configure_softether_service_unit
        systemctl enable --now vpnserver

        rm -f "$archive"
        rm -rf /tmp/vpnserver
    ) >>"$err_file" 2>&1 &
    local pid=$!
    spinner "$pid"
    wait "$pid"
    local exit_status=$?
    local err_content=""
    if [ -s "$err_file" ]; then
        err_content=$(cat "$err_file")
    fi
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        printf '\n%bError during SoftEther installation:%b\n' "$RED" "$RESET"
        [ -n "$err_content" ] && printf '%s\n' "$err_content"
        log_error "SoftEther installation failed."
    fi
    printf '\n'
    log_info "SoftEther installed and running (service: vpnserver). Immediately change the admin password with: vpncmd /SERVER localhost /CMD ServerPasswordSet"
}

uninstall_softether() {
    systemctl disable --now vpnserver >/dev/null 2>&1 || true
    rm -rf /usr/local/vpnserver >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/vpnserver.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
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
    log_info "Setting up network..."
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >> "$LOG_FILE" 2>&1 || log_warn "Unable to enable IP forwarding immediately."
    
    # Detect external interface
    local ext_interface=$(ip route | grep default | awk '{print $5}' | head -1 || echo "eth0")
    
    # Firewall (with duplicate check)
    if command -v ufw &> /dev/null; then
        ufw --force enable >> "$LOG_FILE" 2>&1 || true
        ufw allow 22/tcp >> "$LOG_FILE" 2>&1 || true
        ufw allow 1194/udp >> "$LOG_FILE" 2>&1 || true
        ufw allow 51820/udp >> "$LOG_FILE" 2>&1 || true
        ufw allow 443/tcp >> "$LOG_FILE" 2>&1 || true
        ufw reload >> "$LOG_FILE" 2>&1 || true
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=openvpn >> "$LOG_FILE" 2>&1 || true
        firewall-cmd --permanent --add-port=51820/udp >> "$LOG_FILE" 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >> "$LOG_FILE" 2>&1 || true
        firewall-cmd --reload >> "$LOG_FILE" 2>&1 || true
    else
        $INSTALL_CMD ufw >> "$LOG_FILE" 2>&1 || true
        # Re-run if installed
    fi
    
    # NAT with duplicate removal
    if command -v iptables >/dev/null 2>&1; then
        iptables -t nat -D POSTROUTING -o "$ext_interface" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i wg+ -j ACCEPT 2>/dev/null || true

        iptables -t nat -A POSTROUTING -o "$ext_interface" -j MASQUERADE
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i wg+ -j ACCEPT

        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save >> "$LOG_FILE" 2>&1 || log_warn "Failed to persist iptables rules."
        fi
    else
        log_warn "iptables not found; skipping NAT configuration. Configure manually if required."
    fi
    
    log_info "Network config complete."
}

show_active_services() {
    log_info "Active VPN services overview:"  

    if is_openvpn_installed; then
        ensure_openvpn_service_unit
        if systemctl is-active --quiet "$OPENVPN_SERVICE_UNIT" 2>/dev/null; then
            echo "- OpenVPN: ACTIVE (${OPENVPN_SERVICE_UNIT})"
            echo "  Config: /etc/openvpn/server/server.conf"
            if command -v ss >/dev/null 2>&1; then
                echo "  Sessions: $(ss -u -H state established '( sport = :1194 )' 2>/dev/null | wc -l)"
            elif command -v netstat >/dev/null 2>&1; then
                echo "  Sessions: $(netstat -uln 2>/dev/null | grep -c :1194)"
            fi
        else
            echo "- OpenVPN: INSTALLED (inactive). Start with: systemctl start $OPENVPN_SERVICE_UNIT"
        fi
    else
        echo "- OpenVPN: Not installed"
    fi

    if is_wireguard_installed; then
        if ip link show wg0 >/dev/null 2>&1; then
            echo "- WireGuard: ACTIVE (interface wg0)"
            local wg_status
            wg_status=$(wg show wg0 2>/dev/null || true)
            if [ -n "$wg_status" ]; then
                printf '  %s\n' "$wg_status"
            fi
        else
            echo "- WireGuard: INSTALLED (interface wg0 down). Start with: wg-quick up wg0"
        fi
    else
        echo "- WireGuard: Not installed"
    fi

    if is_softether_installed; then
        if systemctl is-active --quiet vpnserver 2>/dev/null; then
            echo "- SoftEther: ACTIVE (vpnserver service)"
        else
            echo "- SoftEther: INSTALLED (service stopped). Start with: systemctl start vpnserver"
        fi
    else
        echo "- SoftEther: Not installed"
    fi
}

show_certificate_management() {
    log_info "Certificate & User Management"
    echo "For OpenVPN: Use easyrsa in /etc/openvpn/easy-rsa to build/revoke clients."
    echo "For WireGuard: Generate keys and add [Peer] to wg0.conf."
    echo "For SoftEther: Use vpncmd to manage users/hubs."
}

run_vpn_diagnostics() {
    log_info "Running VPN diagnostics..."
    echo ""

    local server_ip=$(hostname -I | awk '{print $1}')
    local issues=0

    if is_openvpn_installed; then
        ensure_openvpn_service_unit
        if systemctl is-active --quiet "$OPENVPN_SERVICE_UNIT" 2>/dev/null; then
            if nc -zu -w3 "$server_ip" 1194 >/dev/null 2>&1; then
                log_info "OpenVPN UDP port 1194 reachable locally."
            else
                log_warn "OpenVPN UDP port 1194 not responding locally."
                issues=$((issues+1))
            fi
            if openvpn --config /etc/openvpn/server/server.conf --test >/dev/null 2>&1; then
                log_info "OpenVPN configuration passes sanity check."
            else
                log_warn "OpenVPN configuration test failed."
                issues=$((issues+1))
            fi
        else
            log_warn "OpenVPN service inactive."
            issues=$((issues+1))
        fi
    fi

    if is_wireguard_installed; then
        if ip link show wg0 >/dev/null 2>&1; then
            if nc -zu -w3 "$server_ip" 51820 >/dev/null 2>&1; then
                log_info "WireGuard UDP port 51820 reachable locally."
            else
                log_warn "WireGuard UDP port 51820 not responding locally."
                issues=$((issues+1))
            fi
            local peer_count
            peer_count=$(wg show wg0 2>/dev/null | grep -c '^peer:' || true)
            log_info "WireGuard peers configured: $peer_count"
        else
            log_warn "WireGuard interface wg0 is down."
            issues=$((issues+1))
        fi
    fi

    if is_softether_installed; then
        if systemctl is-active --quiet vpnserver 2>/dev/null; then
            if nc -z -w3 "$server_ip" 443 >/dev/null 2>&1; then
                log_info "SoftEther TCP port 443 reachable locally."
            else
                log_warn "SoftEther TCP port 443 not responding locally."
                issues=$((issues+1))
            fi
        else
            log_warn "SoftEther service inactive."
            issues=$((issues+1))
        fi
    fi

    echo ""
    if command -v ss >/dev/null 2>&1; then
        ss -tuln | head -n 20
    else
        netstat -tuln | head -n 20
    fi

    echo ""
    show_active_services

    if [ "$issues" -gt 0 ]; then
        log_warn "Diagnostics completed with $issues issue(s). Review warnings above."
    else
        log_info "Diagnostics completed with no blocking issues detected."
    fi
}

show_integration_help() {
    log_info "Integration & Testing Help"
    echo "Ensure firewalls allow VPN ports, test connections from external."
    echo "Test multi-device connectivity."
}

# Security warnings enhanced
check_security_warnings() {
    log_info "🔒 Security audit checks..."
    echo ""

    local warnings=0

    if is_softether_installed && systemctl is-active --quiet vpnserver 2>/dev/null; then
        log_warn "SoftEther default admin password is likely still set to 'adminpassword'. Change it with: vpncmd /SERVER localhost /CMD ServerPasswordSet"
        warnings=$((warnings+1))
    fi

    if is_openvpn_installed; then
        if [ -f /etc/openvpn/easy-rsa/pki/ca.crt ]; then
            log_warn "OpenVPN is using Easy-RSA defaults. Rotate CA, server, and client certificates for production."
            warnings=$((warnings+1))
        fi
    fi

    if is_wireguard_installed && [ -f /etc/wireguard/private.key ]; then
        local key_age=$(stat -c %Y /etc/wireguard/private.key 2>/dev/null || echo "0")
        local now=$(date +%s)
        local age_days=$(( (now - key_age) / 86400 ))
        if [ "$age_days" -lt 1 ]; then
            log_warn "WireGuard keys were just generated. Rotate them regularly and protect /etc/wireguard/."
            warnings=$((warnings+1))
        fi
    fi

    if ! command -v ufw >/dev/null 2>&1 && ! command -v firewall-cmd >/dev/null 2>&1; then
        log_warn "No host firewall detected (ufw or firewalld). Ensure perimeter devices enforce VPN access controls."
        warnings=$((warnings+1))
    fi

    if [ "$warnings" -gt 0 ]; then
        echo ""
        log_warn "$warnings security reminder(s) detected. Address them before deployment."
    else
        log_info "No immediate security findings detected."
    fi
    echo ""
}

# Main
main() {
    check_root
    detect_pkg_manager
    fix_dpkg
    echo "VPN Installer started: $(date)" | tee -a "$LOG_FILE"
    update_system
    install_dependencies
    setup_network_config
    if [ ${#VPN_FLAGS[@]} -gt 0 ]; then
        install_mode  # Use flags
    else
        prompt_mode
    fi
    check_security_warnings
    log_info "Script complete. Check log and change defaults!"
}

main "$@"