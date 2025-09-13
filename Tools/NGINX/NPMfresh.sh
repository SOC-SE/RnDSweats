#!/bin/bash

# ====================================================================================
# Nginx Proxy Manager Setup Script for Ubuntu
#
# This script automates the installation and setup of Nginx Proxy Manager
# running inside a Docker container. It handles the installation of Docker,
# Docker Compose, and configures the necessary files and directories.
# ====================================================================================

# --- Script Configuration ---
# Exit immediately if a command exits with a non-zero status.
set -e

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Function to Print Messages ---
log_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# --- Root User Check ---
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root. Please use sudo."
  exit 1
fi

# --- Step 1: System Detection and Prerequisite Installation ---
log_message "Detecting distribution and installing prerequisites..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=${ID_LIKE:-""} # Set to empty string if not defined
else
    log_warning "Cannot determine OS from /etc/os-release. Aborting."
    exit 1
fi
 
# Determine OS Family and set package manager / docker repo distro
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID" == "linuxmint" || " $OS_ID_LIKE " == *"debian"* ]]; then
    PKG_MANAGER="apt-get"
    log_message "Detected Debian-based system ($OS_ID). Using APT."
    # For Docker repo, ubuntu is ubuntu, everything else (Debian, Mint) uses debian repo
    [ "$OS_ID" = "ubuntu" ] && DOCKER_DISTRO="ubuntu" || DOCKER_DISTRO="debian"
    # Install prerequisites
    $PKG_MANAGER update > /dev/null
    $PKG_MANAGER install -y apt-transport-https ca-certificates curl software-properties-common gpg
elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "centos" || "$OS_ID" == "ol" || "$OS_ID" == "rhel" || " $OS_ID_LIKE " == *"rhel"* || " $OS_ID_LIKE " == *"centos"* ]]; then
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    else
        PKG_MANAGER="yum"
    fi
    log_message "Detected Red Hat-based system ($OS_ID). Using $PKG_MANAGER."
    # For Docker repo, fedora is fedora, everything else (CentOS, Oracle, RHEL, etc.) uses centos repo
    [ "$OS_ID" = "fedora" ] && DOCKER_DISTRO="fedora" || DOCKER_DISTRO="centos"
    # Install prerequisites
    $PKG_MANAGER install -y yum-utils curl
else
    log_warning "Unsupported distribution: '$OS_ID'. This script supports Debian and Red Hat families."
    exit 1
fi

# --- Step 2: Install Docker ---
log_message "Installing Docker..."
if ! command -v docker &> /dev/null; then
    log_message "Docker not found. Proceeding with installation."
    if [ "$PKG_MANAGER" == "apt-get" ]; then
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL "https://download.docker.com/linux/${DOCKER_DISTRO}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DOCKER_DISTRO} $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        $PKG_MANAGER update
        $PKG_MANAGER install -y docker-ce docker-ce-cli containerd.io
    elif [ "$PKG_MANAGER" == "dnf" ] || [ "$PKG_MANAGER" == "yum" ]; then
        yum-config-manager --add-repo "https://download.docker.com/linux/${DOCKER_DISTRO}/docker-ce.repo"
        $PKG_MANAGER install -y docker-ce docker-ce-cli containerd.io
    fi
    log_message "Docker installed successfully."
else
    log_message "Docker is already installed."
fi

# Enable and start the Docker service
systemctl enable docker
systemctl start docker

# --- Step 3: Install Docker Compose ---
log_message "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null
then
    log_message "Docker Compose not found. Proceeding with installation."
    # Get the latest stable release of Docker Compose
    LATEST_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$LATEST_COMPOSE_VERSION" ]; then
        log_warning "Could not fetch latest Docker Compose version. Using a fallback."
        LATEST_COMPOSE_VERSION="1.29.2" # Fallback version
    fi
    log_message "Downloading Docker Compose version ${LATEST_COMPOSE_VERSION}..."
    curl -L "https://github.com/docker/compose/releases/download/${LATEST_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    log_message "Docker Compose installed successfully."
else
    log_message "Docker Compose is already installed."
fi

# --- Step 4: Create Directory and Docker Compose File for Nginx Proxy Manager ---
log_message "Setting up Nginx Proxy Manager configuration..."
mkdir -p /opt/nginx-proxy-manager

# Create the docker-compose.yml file
cat > /opt/nginx-proxy-manager/docker-compose.yml <<EOF
version: '3'
services:
  app:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      # These ports are in format <host-port>:<container-port>
      - '80:80' # Public HTTP Port
      - '443:443' # Public HTTPS Port
      - '666:81' # Admin Web Port
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
EOF

log_message "docker-compose.yml created successfully in /opt/nginx-proxy-manager/"

# --- Step 5: Start Nginx Proxy Manager Container ---
log_message "Starting the Nginx Proxy Manager container..."
cd /opt/nginx-proxy-manager
docker-compose up -d

# --- Final Instructions ---
log_message "Nginx Proxy Manager has been successfully deployed!"
echo -e "${GREEN}You can now access the admin panel by navigating to:${NC}"
echo -e "  ${YELLOW}http://<your-server-ip>:666${NC}"
echo ""
echo -e "${GREEN}Default Administrator User:${NC}"
echo -e "  Email:    ${YELLOW}admin@example.com${NC}"
echo -e "  Password: ${YELLOW}changeme${NC}"
echo ""
log_warning "IMPORTANT: Please log in immediately and change the default email and password!"
echo ""
log_message "Setup complete."