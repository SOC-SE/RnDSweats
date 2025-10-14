#!/bin/bash

# ====================================================================================
# Nginx Proxy Manager Setup Script
#
# This script automates the installation and setup of Nginx Proxy Manager
# running inside a Docker container. It handles the installation of Docker,
# the Docker Compose plugin, and configures the necessary files and directories.
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
    $PKG_MANAGER install -y apt-transport-https ca-certificates curl software-properties-common gpg acl
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
    $PKG_MANAGER install -y yum-utils curl acl
else
    log_warning "Unsupported distribution: '$OS_ID'. This script supports Debian and Red Hat families."
    exit 1
fi

# --- Step 1.5: Conflict Checks ---
log_message "Checking for potential conflicts..."

# Define Apache service name and package based on OS
APACHE_SERVICE=""
APACHE_PKG=""
if [ "$PKG_MANAGER" == "apt-get" ]; then
    APACHE_SERVICE="apache2"
    APACHE_PKG="apache2"
else
    APACHE_SERVICE="httpd"
    APACHE_PKG="httpd"
fi

# Check if Apache is installed
APACHE_INSTALLED=false
if [ "$PKG_MANAGER" == "apt-get" ]; then
    if dpkg -s "$APACHE_PKG" &> /dev/null; then
        APACHE_INSTALLED=true
    fi
else # dnf or yum
    if rpm -q "$APACHE_PKG" &> /dev/null; then
        APACHE_INSTALLED=true
    fi
fi

if [ "$APACHE_INSTALLED" = true ]; then
    log_warning "Apache ($APACHE_SERVICE) is installed on this system."
    log_warning "Nginx Proxy Manager requires ports 80 and 443, which Apache may be using."
    echo "Please choose how to proceed:"
    echo "  1) Stop and disable Apache (recommended)"
    echo "  2) Uninstall Apache completely"
    echo "  3) Abort installation"
    read -p "Enter your choice (1-3): " apache_choice

    case "$apache_choice" in
        1)
            log_message "Stopping and disabling Apache..."
            systemctl stop "$APACHE_SERVICE" &>/dev/null || true
            systemctl disable "$APACHE_SERVICE" &>/dev/null || true
            log_message "Apache has been stopped and disabled."
            ;;
        2)
            log_message "Uninstalling Apache..."
            $PKG_MANAGER remove -y "$APACHE_PKG"* > /dev/null
            log_message "Apache has been uninstalled."
            ;;
        3)
            log_warning "Aborting installation as requested."
            exit 0
            ;;
        *)
            log_warning "Invalid choice. Aborting installation."
            exit 1
            ;;
    esac
fi

# Check for ports 80, 443, 666
log_message "Checking for required ports..."
PORTS_TO_CHECK=(80 443 666)
CONFLICT_FOUND=false
for port in "${PORTS_TO_CHECK[@]}"; do
    # Use ss to check for listening TCP ports
    if ss -tln | grep -q ":${port}\s"; then
        PROCESS_INFO=$(ss -tlnp | grep ":${port}\s" || true)
        log_warning "Port ${port} is already in use."
        if [ -n "$PROCESS_INFO" ]; then
            log_warning "Process details: ${PROCESS_INFO}"
        fi
        CONFLICT_FOUND=true
    fi
done

if [ "$CONFLICT_FOUND" = true ]; then
    log_warning "One or more required ports are in use. Please free them up and run the script again."
    exit 1
fi

log_message "No port conflicts found."

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

# --- Step 3: Install Docker Compose Plugin ---
log_message "Installing Docker Compose plugin..."
if ! docker compose version &>/dev/null; then
    log_message "Docker Compose plugin not found. Proceeding with installation."
    $PKG_MANAGER install -y docker-compose-plugin
    log_message "Docker Compose plugin installed successfully."
else
    log_message "Docker Compose plugin is already installed."
fi

# --- Step 4: Create Directory and Docker Compose File for Nginx Proxy Manager ---
log_message "Setting up Nginx Proxy Manager configuration..."
mkdir -p /opt/nginx-proxy-manager
cd /opt/nginx-proxy-manager

# Download config requirements
wget https://raw.githubusercontent.com/openappsec/openappsec/main/deployment/docker-compose/nginx-proxy-manager/docker-compose.yaml
log_message "docker-compose.yml created successfully in /opt/nginx-proxy-manager/"
wget https://raw.githubusercontent.com/openappsec/openappsec/main/deployment/docker-compose/nginx-proxy-manager/.env
log_message ".env created successfully in /opt/nginx-proxy-manager/"
mkdir ./appsec-localconfig
wget https://raw.githubusercontent.com/openappsec/open-appsec-npm/main/deployment/managed-from-npm-ui/local_policy.yaml -O ./appsec-localconfig/local_policy.yaml
log_message "Declaritive config created in /opt/nginx-proxy-manager/appsec-localconfig"

# --- Step 5: Start Nginx Proxy Manager Container ---
log_message "Starting the Nginx Proxy Manager container..."
docker compose up -d

# --- Step 6: Set Permissions for Wazuh Integration ---
log_message "Checking for Wazuh agent for log integration..."
NPM_LOG_DIR="/opt/nginx-proxy-manager/data/logs"

# Wait a moment for the log directory to be created by the container
sleep 5

if getent group wazuh &>/dev/null; then
    log_message "Wazuh group found on the system."
    read -p "Do you want to grant the wazuh group read access to NPM logs? (y/n): " confirm_wazuh
    if [[ "$confirm_wazuh" == [yY] ]]; then
        if [ -d "$NPM_LOG_DIR" ]; then
            log_message "Applying ACLs to NPM log directory for Wazuh..."
            setfacl -R -m g:wazuh:rX "$NPM_LOG_DIR"
            setfacl -dR -m g:wazuh:rX "$NPM_LOG_DIR"
            log_message "Wazuh integration permissions applied."
        else
            log_warning "NPM log directory not found at $NPM_LOG_DIR. Skipping ACL setup."
        fi
    else
        log_message "Skipping Wazuh ACL setup as requested."
    fi
else
    log_message "Wazuh group not found. Skipping ACL setup."
fi

# --- Final Instructions ---
log_message "Nginx Proxy Manager has been successfully deployed!"
echo -e "${GREEN}You can now access the admin panel by navigating to:${NC}"
echo -e "  ${YELLOW}http://<your-server-ip>:81${NC}"
echo ""
echo -e "${GREEN}Default Administrator User:${NC}"
echo -e "  Email:    ${YELLOW}admin@example.com${NC}"
echo -e "  Password: ${YELLOW}changeme${NC}"
echo ""
log_warning "IMPORTANT: Please log in immediately and change the default email and password!"
echo ""
log_message "Setup complete."
