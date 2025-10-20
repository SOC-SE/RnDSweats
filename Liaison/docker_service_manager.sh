#!/bin/bash

# =============================================================================
# Docker Service Manager Script
# Overview:
# Menu-driven script to dockerize security services from Version_1/Version_2 (e.g., VPN, IDS).
# Detects installed services, migrates to containers with backups, or sets up new. Uses official/custom
# images, advanced Docker flags for security/control.
#
# Key Features:
# - Detection: systemctl/dpkg/ps for 8 services (e.g., vsftpd, OpenVPN).
# - Menu: Scan, Manage (dockerize/skip), Setup, Logs, Stop.
# - Auto: Installs Docker, backups configs, Compose support, custom Dockerfiles from your scripts.
#
# Compatibility: Ubuntu/Debian (apt/systemd); Bash 4+; sudo required.
# Prerequisites: Network, original scripts, 5GB disk.
#
# Usage:
# 1. chmod +x docker_service_manager.sh
# 2. sudo bash docker_service_manager.sh
# 3. Menu options: 1=Install Docker, 2=Scan, 3=Manage (e.g., 'vpn'), 4=Setup new, etc.
#
# Limitations: Basic detection/builds; Linux-only.
# Security: no-new-privileges, read-only, limited caps/volumes.
#
# =============================================================================
# Usage Instructions:
# 1. Preparation: Place this script in the project root (alongside Version_1/Version_2). Make executable:
#    chmod +x docker_service_manager.sh
# 2. Execution: Run with sudo: sudo bash docker_service_manager.sh
# 3. Menu Navigation:
#    - Option 1: Install/Verify Docker - Auto-installs if missing, using @Docker_install.sh (Version_1) if present,
#      or apt for docker.io + docker-compose. Starts/enables Docker service.
#    - Option 2: Scan for Installed Services - Lists all services (detected in green, not in yellow).
#      Example output: "Detected: File Transfer Server (vsftpd/SFTP) (file_transfer)"
#    - Option 3: Manage Specific Service - Scans first, then prompts for key (e.g., 'vpn' or 'all').
#      For each: Checks if already dockerized (manages existing container), else prompts "Dockerize? (y/n)".
#      If yes, optional Compose (y/n), then auto-migrates (backup, stop host, setup container).
#    - Option 4: Setup New Service in Docker - Lists available keys/names; prompts key and Compose choice.
#      Builds/runs fresh (e.g., for 'ids', pulls honeycomb/suricata, runs @IDS.sh logic).
#    - Option 5: View Docker Containers/Logs - Runs 'docker ps -a' to list all; prompts container name for logs (tail -20).
#    - Option 6: Stop All Dockerized Services - Stops containers matching '*-container' pattern.
#    - Option 7: View Docker Related Commands - Displays a list of Docker commands used in the script and additional useful commands.
#    - Option 8: Exit - Clean exit (0).
# 4. Post-Usage: Manage containers manually (e.g., docker start file_transfer-container), edit generated files
#    (Dockerfile.vpn, docker-compose.honeypot.yml), or remove (docker rm). Backups in ./docker_backups/service/.
# 5. Customization: Edit SERVICES array for new detections/images; enhance backup_host_config() for unique paths.


echo -e "${GREEN}
 ____             _      ___ _   _ 
|  _ \  ___   ___| | __ |_ _| |_| |
| | | |/ _ \ / __| |/ /  | || __| |
| |_| | (_) | (__|   <   | || |_|_|
|____/ \___/ \___|_|\_\ |___|\__(_)
                                                        
  Welcome to Docker Service Manager - Secure Your Services with Containers!
${NC}"

# Note: The ASCII art above is a simple 'Docker' themed banner. For a more elaborate one, use:
# figlet "Docker Manager" > banner.txt and echo "$(cat banner.txt)".

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'

set -euo pipefail

# TeamPack compliance: confirm authorized environment
teampack_confirm() {
    read -p "Confirm you will run this only on your authorized team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}
teampack_confirm

# Package manager detection for cross-distro support
PKG_MANAGER=""
INSTALL_CMD=""
UPDATE_CMD=""

detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf -y makecache"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum makecache -y"
    else
        echo -e "${RED}Unsupported package manager. Install Docker manually.${NC}"
        exit 1
    fi
}

get_compose_command() {
    if command -v docker-compose &> /dev/null; then
        printf 'docker-compose'
        return 0
    fi
    if docker compose version &> /dev/null; then
        printf 'docker compose'
        return 0
    fi
    echo -e "${YELLOW}Docker Compose is not installed. Attempting to install compose plugin...${NC}"
    install_compose_plugin
    if command -v docker-compose &> /dev/null; then
        printf 'docker-compose'
        return 0
    fi
    if docker compose version &> /dev/null; then
        printf 'docker compose'
        return 0
    fi
    echo -e "${RED}Docker Compose is unavailable. Install docker-compose or the compose plugin and rerun.${NC}"
    return 1
}

package_installed() {
    local pkg=$1
    if command -v dpkg &> /dev/null; then
        dpkg -s "$pkg" >/dev/null 2>&1
    elif command -v rpm &> /dev/null; then
        rpm -q "$pkg" >/dev/null 2>&1
    else
        return 1
    fi
}

ensure_package_from_candidates() {
    detect_pkg_manager
    local pkg
    for pkg in "$@"; do
        if [[ -z $pkg ]]; then
            continue
        fi
        if package_installed "$pkg"; then
            return 0
        fi
        if $INSTALL_CMD "$pkg" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

install_compose_plugin() {
    case "$PKG_MANAGER" in
        "apt")
            $UPDATE_CMD >/dev/null 2>&1 || true
            ensure_package_from_candidates docker-compose-plugin docker-compose >/dev/null 2>&1 || true
            ;;
        "dnf"|"yum")
            ensure_package_from_candidates docker-compose-plugin docker-compose docker-compose-plugin.noarch >/dev/null 2>&1 || true
            ;;
        *)
            return 1
            ;;
    esac
}

# Fixed SERVICES array with consistent 5 fields: name|check_cmd|host_svc|image|ports|caps|pkg_check (added missing)
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

# Function to install Docker if missing
install_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}Docker not found. Installing...${NC}"
        if [ -f "Version_1/Docker_install.sh" ]; then
            bash Version_1/Docker_install.sh
        else
            apt update &> /dev/null
            apt install -y docker.io docker-compose &> /dev/null
            systemctl start docker
            systemctl enable docker
        fi
        echo -e "${GREEN}Docker installed.${NC}"
    else
        echo -e "${GREEN}Docker is already installed.${NC}"
    fi
}

# Function to check if service is installed/detected
is_service_installed() {
    local service_key=$1
    IFS='|' read -r name check_cmd host_svc image ports caps pkg_check <<< "${SERVICES[$service_key]}"
    if [[ $check_cmd != "none" ]]; then
        if command -v systemctl &> /dev/null && systemctl is-active --quiet "$host_svc" 2>/dev/null; then
            return 0  # Active systemd service
        fi
        if [[ -n $pkg_check ]]; then
            for pkg in $pkg_check; do
                if package_installed "$pkg"; then
                    return 0
                fi
            done
        fi
        if [[ $check_cmd == "ps"* ]] && ps aux | grep -q "$(echo $check_cmd | cut -d' ' -f3)"; then
            return 0  # Process running
        fi
    fi
    return 1  # Not detected
}

# Function to backup host service config (simple: copy common dirs)
backup_host_config() {
    local service_key=$1
    case $service_key in
        "file_transfer") rsync -a /etc/vsftpd/ /backup/vsftpd/ 2>/dev/null || true ;;
        "vpn") rsync -a /etc/openvpn/ /backup/openvpn/ 2>/dev/null || true ;;
        "honeypot") rsync -a /opt/cowrie/ /backup/cowrie/ 2>/dev/null || true ;;
        "fim") rsync -a /var/ossec/ /backup/ossec/ 2>/dev/null || true ;;
        "ids") rsync -a /etc/suricata/ /backup/suricata/ 2>/dev/null || true ;;
        *) echo "No backup defined for $service_key" ;;
    esac
    mkdir -p /backup
}

# Function to stop host service
stop_host_service() {
    local service_key=$1
    IFS='|' read -r name check_cmd host_svc image ports caps pkg_check <<< "${SERVICES[$service_key]}"
    if [[ $host_svc != "" ]]; then
        systemctl stop "$host_svc" 2>/dev/null || true
        echo -e "${GREEN}Stopped host service: $host_svc${NC}"
    fi
}

# Function to setup Docker for service (pull/build, run with advanced options)
setup_docker_service() {
    local service_key=$1
    local use_compose=$2  # true for compose
    IFS='|' read -r name check_cmd host_svc image ports caps pkg_check <<< "${SERVICES[$service_key]}"

    # Create backup dir
    mkdir -p ./docker_backups
    backup_host_config "$service_key"

    # Stop host if running
    stop_host_service "$service_key"

    # Pull image or build custom if needed (e.g., for script-based)
    if [[ $image != "" ]]; then
        docker pull "$image"
    else
        # Placeholder for custom build: e.g., create Dockerfile with your script
        echo -e "${YELLOW}No official image; building custom...${NC}"
        # Example custom Dockerfile (adapt per service)
        cat > Dockerfile.$service_key << EOF
FROM ubuntu:22.04
RUN apt update && apt install -y $(echo $pkg_check | cut -d' ' -f4-)  # Install deps
COPY $(echo $service_key | tr '_' '-').sh /app/setup.sh  # Assume script copied
RUN chmod +x /app/setup.sh
ENTRYPOINT ["/app/setup.sh"]
EOF
        docker build -t custom_$service_key -f Dockerfile.$service_key .
        image="custom_$service_key"
    fi

    # Common Docker run options: security, restart, logs
    local run_opts="--name $service_key-container --restart=unless-stopped --security-opt no-new-privileges --read-only -v ./docker_backups/$service_key:/config:ro"
    if [[ $ports != "none" ]]; then
        run_opts="$run_opts -p $ports"
    fi
    if [[ $caps != "" ]]; then
        run_opts="$run_opts $caps"
    fi
    # Volumes for persistence (adapt per service)
    case $service_key in
        "file_transfer") run_opts="$run_opts -v /shared/files:/var/ftp" ;;
        "vpn") run_opts="$run_opts -v /etc/openvpn:/vpn" ;;
        "honeypot") run_opts="$run_opts -v /opt/cowrie:/cowrie" ;;
        "fim") run_opts="$run_opts -v /host/files:/monitor:ro" ;;  # Mount host dir to monitor
        "ids") run_opts="$run_opts --network=host" ;;
        *) run_opts="$run_opts -v /tmp:/data" ;;  # Default
    esac
    run_opts="$run_opts -d"  # Detached

    if [[ $use_compose == "true" ]]; then
        # Generate simple docker-compose.yml
        cat > docker-compose.$service_key.yml << EOF
version: '3'
services:
  $service_key:
    image: $image
    container_name: $service_key-container
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    ports:
$(if [[ $ports != "none" ]]; then echo "      - \"$ports\""; fi)
    volumes:
      - ./docker_backups/$service_key:/config:ro
$(case $service_key in
    "file_transfer") echo "      - /shared/files:/var/ftp" ;;
    "vpn") echo "      - /etc/openvpn:/vpn" ;;
    # Add more...
esac)
$(if [[ $caps != "" ]]; then echo "    cap_add: [NET_ADMIN]"; fi)
    devices:
$(if [[ $caps == *tun* ]]; then echo "      - /dev/net/tun:/dev/net/tun"; fi)
EOF
        docker-compose -f docker-compose.$service_key.yml up -d
        echo -e "${GREEN}Started via Compose: docker-compose.$service_key.yml${NC}"
    else
        docker run $run_opts "$image"
        echo -e "${GREEN}Started container: $service_key-container${NC}"
        echo -e "${YELLOW}Logs: docker logs $service_key-container${NC}"
        echo -e "${YELLOW}Stop: docker stop $service_key-container${NC}"
    fi
}

# Function to check all services
scan_services() {
    echo -e "${YELLOW}Scanning for installed services...${NC}"
    local detected=()
    for key in "${!SERVICES[@]}"; do
        IFS='|' read -r name <<< "${SERVICES[$key]}"
        if is_service_installed "$key"; then
            detected+=("$key")
            echo -e "${GREEN}Detected: $name ($key)${NC}"
        else
            echo -e "${YELLOW}Not detected: $name ($key)${NC}"
        fi
    done
    if [[ ${#detected[@]} -eq 0 ]]; then
        echo -e "${RED}No services detected.${NC}"
    fi
    echo "Detected count: ${#detected[@]}"
}

# Menu function (uses select for simple menu; install dialog for fancier if wanted)
show_menu() {
    echo -e "\n${GREEN}=== Docker Service Manager ===${NC}"
    echo "1. Install/Verify Docker"
    echo "2. Scan for Installed Services"
    echo "3. Manage Specific Service (Dockerize or Skip)"
    echo "4. Setup New Service in Docker (from scratch)"
    echo "5. View Docker Containers/Logs"
    echo "6. Stop All Dockerized Services"
    echo "7. View Docker Related Commands"
    echo "8. Exit"
    read -p "Choose option: " choice
    case $choice in
        1) install_docker ;;
        2) scan_services ;;
        3)
            scan_services
            read -p "Enter service key to manage (e.g., file_transfer, or 'all'): " svc
            if [[ $svc == "all" ]]; then
                for key in "${!SERVICES[@]}"; do
                    if is_service_installed "$key"; then
                        manage_service "$key"
                    fi
                done
            elif [[ -n ${SERVICES[$svc]} ]]; then
                manage_service "$svc"
            else
                echo -e "${RED}Invalid key.${NC}"
            fi
            ;;
        4)
            echo "Available services to setup in Docker:"
            for key in "${!SERVICES[@]}"; do
                IFS='|' read -r name <<< "${SERVICES[$key]}"
                echo "- $key: $name"
            done
            read -p "Enter service key: " svc
            if [[ -n ${SERVICES[$svc]} ]]; then
                read -p "Use Docker Compose? (y/n): " compose_choice
                local compose="false"
                [[ $compose_choice == "y" ]] && compose="true"
                setup_docker_service "$svc" "$compose"
            else
                echo -e "${RED}Invalid key.${NC}"
            fi
            ;;
        5)
            docker ps -a
            read -p "Enter container name for logs: " cont
            docker logs "$cont" | tail -20
            ;;
        6)
            docker stop $(docker ps -q --filter "name=*-container") 2>/dev/null || true
            echo -e "${GREEN}Stopped all managed containers.${NC}"
            ;;
        7) view_docker_commands ;;
        8) exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

# Function to manage (prompt dockerize or skip)
manage_service() {
    local service_key=$1
    IFS='|' read -r name <<< "${SERVICES[$service_key]}"
    echo -e "\n${YELLOW}Managing: $name ($service_key)${NC}"
    # Check if already dockerized
    if docker ps --filter "name=$service_key-container" --format "table {{.Names}}" | grep -q .; then
        echo -e "${GREEN}Already dockerized. Options: restart (docker restart), stop (docker stop), or remove.${NC}"
        read -p "Action (restart/stop/remove/none): " action
        case $action in
            restart) docker restart $service_key-container ;;
            stop) docker stop $service_key-container ;;
            remove) docker rm -f $service_key-container ;;
        esac
        return
    fi
    read -p "Dockerize this service? (y: auto-setup in Docker, n: keep on host): " dockerize
    if [[ $dockerize == "y" ]]; then
        read -p "Use Docker Compose for management? (y/n): " compose_choice
        local compose="false"
        [[ $compose_choice == "y" ]] && compose="true"
        setup_docker_service "$service_key" "$compose"
    else
        echo -e "${GREEN}Keeping on host. To start: systemctl start $(echo ${SERVICES[$service_key]} | cut -d'|' -f3)${NC}"
    fi
}

# Function to view Docker commands
view_docker_commands() {
    echo -e "${GREEN}=== Docker Related Commands ===${NC}"
    echo "Commands used in this script:"
    echo "- docker pull <image>: Pulls the specified Docker image from a registry."
    echo "- docker build -t <tag> -f <dockerfile> . : Builds a Docker image from a Dockerfile."
    echo "- docker run [options] <image>: Runs a container from the image with given options."
    echo "- docker-compose -f <file> up -d: Starts services defined in a compose file in detached mode."
    echo "- docker ps -a: Lists all containers, including stopped ones."
    echo "- docker logs <container>: Shows logs from the specified container."
    echo "- docker stop <container>: Stops the running container."
    echo "- docker restart <container>: Restarts the container."
    echo "- docker rm -f <container>: Forces removal of a container."
    echo ""
    echo "Additional useful Docker commands:"
    echo "- docker start <container>: Starts a stopped container."
    echo "- docker exec -it <container> <command>: Runs a command inside a running container interactively."
    echo "- docker images: Lists all local Docker images."
    echo "- docker rmi <image>: Removes a Docker image."
    echo "- docker volume ls: Lists Docker volumes."
    echo "- docker network ls: Lists Docker networks."
}

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Verify Docker
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Run Version_1/Docker_install.sh first."
    exit 1
fi

# Main loop
echo -e "${GREEN}Welcome to Docker Service Manager!${NC}"
echo "This script handles dockerizing services from your Version_1/Version_2 scripts."
echo "Ensure scripts are in place for custom builds. Run with sudo for full access."
while true; do
    show_menu
done
