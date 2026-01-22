#!/bin/bash

# ==============================================================================
# Script Name: install_technitium.sh
# Description: Installs Technitium DNS Server using Docker Compose with Host Networking
# ==============================================================================

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. Check for Root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Error: Please run as root (sudo).${NC}"
  exit 1
fi

echo -e "${GREEN}Starting Technitium DNS Docker Installer...${NC}"

# 2. Check Dependencies
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed.${NC}"
    echo "Please install Docker first: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

# 3. Configuration Variables
INSTALL_DIR="/opt/technitium-dns"
WEB_PORT="5380"

# 4. Check Port 53 Availability
# Most modern Linux distros (Ubuntu/Debian/Fedora) run systemd-resolved on port 53.
# This prevents Technitium from starting unless fixed.
if ss -tuln | grep -q ":53 "; then
    echo -e "${YELLOW}[!] Warning: Port 53 is currently in use.${NC}"
    echo "    This is commonly caused by 'systemd-resolved'."
    echo "    If the container fails to start, you must disable the system stub listener."
    echo "    See the README or official Technitium docs for the 'systemd-resolved' fix."
    echo "    Attempting to proceed..."
    sleep 3
fi

# 5. Create Directory Structure
echo -e "${GREEN}[+] Creating configuration directories at ${INSTALL_DIR}...${NC}"
mkdir -p "$INSTALL_DIR/config"

# 6. Create docker-compose.yml
# We use network_mode: host for better performance and client IP visibility.
# Note: In host mode, mapped ports (-p) are ignored; the app binds directly to the host network.
echo -e "${GREEN}[+] Generating docker-compose.yml...${NC}"
cat > "$INSTALL_DIR/docker-compose.yml" <<EOF
services:
  dns-server:
    container_name: technitium-dns
    image: technitium/dns-server:latest
    hostname: dns-server
    # Host networking is recommended for DNS servers to see client IPs 
    # and is required if you plan to use the DHCP server feature.
    network_mode: host
    restart: unless-stopped
    environment:
      - DNS_SERVER_DOMAIN=dns-server
      - TZ=UTC
      # Web Console Port (Default is 5380)
      - DNS_SERVER_WEB_SERVICE_HTTP_PORT=${WEB_PORT}
    volumes:
      - ./config:/etc/dns
    sysctls:
      - net.ipv4.ip_local_port_range=1024 65535
EOF

# 7. Start the Service
echo -e "${GREEN}[+] Starting Technitium DNS container...${NC}"
cd "$INSTALL_DIR" || exit
docker compose up -d

# 8. Status Check & Output
if [ $? -eq 0 ]; then
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo -e "----------------------------------------------------------------"
    echo -e "${GREEN}Success! Technitium DNS is running.${NC}"
    echo -e "----------------------------------------------------------------"
    echo -e "Web Console:   ${YELLOW}http://${HOST_IP}:${WEB_PORT}${NC}"
    echo -e "Default User:  ${YELLOW}admin${NC}"
    echo -e "Default Pass:  ${YELLOW}admin${NC}"
    echo -e "Config Location: $INSTALL_DIR"
    echo -e "----------------------------------------------------------------"
    echo -e "${YELLOW}IMPORTANT:${NC} Log in immediately and change the default password."
else
    echo -e "${RED}Error: Failed to start the container.${NC}"
    echo "Check logs with: docker logs technitium-dns"
fi