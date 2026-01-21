#!/bin/bash

# ==========================================
# Elastic Agent Installer
# Usage: sudo ./install_agent.sh [SERVER_IP]
# ==========================================

# 1. Set Server IP (Default or Argument)
SERVER_IP="172.20.242.20"

if [ ! -z "$1" ]; then
    SERVER_IP="$1"
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Target Fleet Server: https://$SERVER_IP:8220${NC}"

# 2. OS Detection & Installation Functions
RHEL() {
    echo -e "${GREEN}Detected RHEL/CentOS/Oracle Linux.${NC}"
    echo "Downloading RPM..."
    curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.2-x86_64.rpm
    
    echo "Installing RPM..."
    rpm -ivh elastic-agent-8.13.2-x86_64.rpm
}

DEBIAN() {
    echo -e "${GREEN}Detected Debian/Ubuntu.${NC}"
    echo "Downloading DEB..."
    wget -q https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.2-amd64.deb
    
    echo "Installing DEB..."
    dpkg -i elastic-agent-8.13.2-amd64.deb
}

# 3. Execution Logic
if command -v yum >/dev/null; then
    RHEL
elif command -v apt-get >/dev/null; then
    DEBIAN
else
    echo -e "${RED}Unsupported Operating System.${NC}"
    exit 1
fi

# 4. Enrollment (Interactive)
echo ""
echo -e "${BLUE}--- Agent Installed ---${NC}"
echo "To connect this agent, you need the Enrollment Token from your Kibana server."
echo "Location: Kibana > Fleet > Agents > Add Agent"
echo ""
read -p "Paste Enrollment Token here (leave empty to skip): " TOKEN

if [ -z "$TOKEN" ]; then
    echo -e "${RED}Skipping enrollment.${NC}"
    echo "You can enroll later using:"
    echo "sudo elastic-agent enroll --url=https://$SERVER_IP:8220 --enrollment-token=<TOKEN> --insecure"
else
    echo -e "${GREEN}Enrolling Agent...${NC}"
    # Enroll the agent
    # --insecure is used because self-hosted labs usually use self-signed certs
    elastic-agent enroll \
      --url="https://$SERVER_IP:8220" \
      --enrollment-token="$TOKEN" \
      --insecure \
      --force

    echo -e "${GREEN}Enable Service...${NC}"
    systemctl daemon-reload
    systemctl enable --now elastic-agent
    
    echo -e "${BLUE}Status:${NC}"
    systemctl status elastic-agent --no-pager
fi