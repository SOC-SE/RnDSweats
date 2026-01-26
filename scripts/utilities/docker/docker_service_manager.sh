#!/bin/bash

# Docker Service Manager Script

# Menu-driven script to dockerize security services. Detects installed services, migrates to containers.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Fixed SERVICES array with consistent 6 fields: name|check_cmd|host_svc|image|ports|caps|pkg_check
declare -A SERVICES=(
    ["file_transfer"]="File Transfer Server (vsftpd/SFTP)|systemctl is-active vsftpd|vsftpd|fauria/vsftpd|20:20,21:21,22:22||vsftpd"
    ["vpn"]="VPN Server (OpenVPN/WireGuard)|systemctl is-active openvpn||kylemanna/docker-openvpn|1194:1194/udp|--cap-add=NET_ADMIN --device=/dev/net/tun|openvpn wireguard-tools"
    ["honeypot"]="Honeypot (Cowrie)|systemctl is-active cowrie||cowrie/cowrie|2222:2222,8022:8022||"
    ["pcap_tshark"]="PCAP Analyzer (Tshark)|systemctl is-active tshark-daemon||ghcr.io/wireshark/tshark|none (ephemeral)||tshark"
    ["fim"]="FIM (OSSEC/AIDE)|systemctl is-active ossec||jasonish/ossec|1514:1514/udp||ossec-hids aide"
    ["ids"]="IDS (Suricata)|systemctl is-active suricata||honeycomb/suricata|8300:8300/udp --network=host|--cap-add=NET_ADMIN|suricata"
    ["scanner_tshark"]="Network Scanner Tshark|none||ghcr.io/wireshark/tshark|none (ephemeral)||tshark"
    ["scanner_nmap"]="Network Scanner Nmap|none||instrumentisto/nmap|none (ephemeral) --privileged||nmap"
)

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Package manager detection
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf makecache -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum makecache -y"
    else
        log_error "Unsupported package manager."
    fi
    log_info "Package manager: $PKG_MANAGER"
}

package_installed() {
    local pkg=$1
    command -v dpkg &> /dev/null && dpkg -s "$pkg" >/dev/null 2>&1
    command -v rpm &> /dev/null && rpm -q "$pkg" >/dev/null 2>&1
}

# Install Docker if missing
install_docker() {
    command -v docker &> /dev/null || {
        log_info "Installing Docker..."
        if [ -f "../Version_1/Docker_install.sh" ]; then
            bash ../Version_1/Docker_install.sh
        else
            $UPDATE_CMD &> /dev/null
            $INSTALL_CMD docker.io docker-compose &> /dev/null
            systemctl start docker
            systemctl enable docker
        fi
    }
}

# Check service installed
is_service_installed() {
    local service_key=$1
    IFS='|' read -r name check_cmd host_svc image ports caps pkg_check <<< "${SERVICES[$service_key]}"
    [[ $check_cmd == "none" ]] && return 1
    command -v systemctl &> /dev/null && systemctl is-active --quiet "$host_svc" 2>/dev/null
    [[ -n $pkg_check ]] && for pkg in $pkg_check; do package_installed "$pkg" && return 0; done
}

backup_host_config() {
    local service_key=$1
    mkdir -p ./docker_backups
    case $service_key in
        "file_transfer") rsync -a /etc/vsftpd/ ./docker_backups/vsftpd/ 2>/dev/null || true ;;
        "vpn") rsync -a /etc/openvpn/ ./docker_backups/openvpn/ 2>/dev/null || true ;;
        *) log_warn "No backup for $service_key" ;;
    esac
}

stop_host_service() {
    local service_key=$1
    IFS='|' read -r _ _ host_svc _ _ _ <<< "${SERVICES[$service_key]}"
    [[ -n $host_svc ]] && systemctl stop "$host_svc" 2>/dev/null || true
}

setup_docker_service() {
    local service_key=$1
    IFS='|' read -r name _ host_svc image ports caps pkg_check <<< "${SERVICES[$service_key]}"
    backup_host_config "$service_key"
    stop_host_service "$service_key"

    docker pull "$image" || log_error "Failed to pull $image"

    local run_opts="--name ${service_key}-container --restart=unless-stopped --security-opt no-new-privileges --read-only"
    [[ $ports != "none" ]] && run_opts+=" -p $ports"
    [[ -n $caps ]] && run_opts+=" $caps"
    run_opts+=" -d $image"

    # shellcheck disable=SC2086  # Intentional word splitting for docker options
    docker run $run_opts || log_error "Failed to start container for $service_key"
    log_info "Started $service_key container."
}

scan_services() {
    log_info "Scanning services..."
    local count=0
    for key in "${!SERVICES[@]}"; do
        IFS='|' read -r name <<< "${SERVICES[$key]}"
        if is_service_installed "$key"; then
            echo -e "${GREEN}Detected: $name ($key)${NC}"
            ((count++))
        else
            echo -e "${YELLOW}Not found: $name ($key)${NC}"
        fi
    done
    [[ $count -gt 0 ]] || log_warn "No services detected."
}

manage_service() {
    local service_key=$1
    IFS='|' read -r name <<< "${SERVICES[$service_key]}"
    echo -e "\n${YELLOW}Managing $name${NC}"
    if docker ps --filter "name=${service_key}-container" --format "table {{.Names}}" | grep -q .; then
        log_info "Already dockerized. Use docker commands to manage."
        return
    fi
    read -r -p "Dockerize? (y/n): " dockerize
    [[ $dockerize =~ ^[Yy]$ ]] && setup_docker_service "$service_key"
}

show_menu() {
    echo -e "\n${GREEN}=== Docker Service Manager ===${NC}"
    echo "1. Install Docker (if needed)"
    echo "2. Scan Services"
    echo "3. Manage Service (dockerize)"
    echo "4. View Containers"
    echo "5. Stop Containers"
    echo "6. Exit"
    read -r -p "Choice: " choice
    case $choice in
        1) install_docker ;;
        2) scan_services ;;
        3)
            scan_services
            read -r -p "Service key: " svc
            if [[ -n ${SERVICES[$svc]:-} ]]; then
                manage_service "$svc"
            else
                log_warn "Invalid key."
            fi
            ;;
        4) docker ps -a ;;
        # shellcheck disable=SC2046  # Intentional word splitting for container IDs
        5) docker stop $(docker ps -q --filter "name=*-container") 2>/dev/null || true ;;
        6) exit 0 ;;
        *) log_warn "Invalid." ;;
    esac
}

# Root check
[[ $(id -u) -ne 0 ]] && log_error "Run as root."

# Main
detect_pkg_manager
install_docker
while true; do show_menu; done
