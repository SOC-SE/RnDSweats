#!/bin/bash

# ====================================================================================
# Dnsmasq Custom Setup Script
#
# This script installs and configures dnsmasq to use custom settings.
# It sets the upstream DNS to Google's servers and configures a specific
# listening port and IP address.
# ====================================================================================

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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
  log_warning "This script requires root privileges. Please run it with sudo."
  exit 1
fi

# --- Step 1: Detect Distro and Install dnsmasq ---
log_message "Detecting distribution and installing dnsmasq..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=${ID_LIKE:-""}
else
    log_warning "Cannot determine OS from /etc/os-release. Aborting."
    exit 1
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID" == "linuxmint" || " $OS_ID_LIKE " == *"debian"* ]]; then
    PKG_MANAGER="apt-get"
    log_message "Detected Debian-based system. Using APT. Updating package lists..."
    $PKG_MANAGER update > /dev/null
elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "centos" || "$OS_ID" == "ol" || "$OS_ID" == "rhel" || " $OS_ID_LIKE " == *"rhel"* ]]; then
    command -v dnf &> /dev/null && PKG_MANAGER="dnf" || PKG_MANAGER="yum"
    log_message "Detected Red Hat-based system. Using $PKG_MANAGER."
else
    log_warning "Unsupported distribution: '$OS_ID'. Aborting."
    exit 1
fi
$PKG_MANAGER install -y dnsmasq

# --- Step 2: Create Custom Configuration File ---
log_message "Configuring dnsmasq with custom settings..."

# This will create a new configuration file in /etc/dnsmasq.d/
cat > /etc/dnsmasq.d/02-custom.conf <<EOF
# --- Custom Configuration ---

# Set the upstream DNS servers
server=8.8.8.8
server=8.8.4.4

# Don't read /etc/resolv.conf for upstream servers
no-resolv

# Increase the cache size
cache-size=1000

# Set the listening port to 5353
port=5353

# Set the listening address.
listen-address=127.0.0.1
EOF

log_message "Configuration file created at /etc/dnsmasq.d/02-custom.conf"

# --- Step 3: Restart and Enable the dnsmasq Service ---
log_message "Restarting dnsmasq service to apply changes..."
systemctl restart dnsmasq

log_message "Enabling dnsmasq service to start on boot..."
systemctl enable dnsmasq

# --- Final Instructions ---
log_message "Dnsmasq has been successfully installed and configured."
echo ""
echo -e "${GREEN}To use it, you must configure your system's network settings to use${NC}"
echo -e "${YELLOW}127.0.0.1${NC} ${GREEN}as the DNS server and point to port${NC} ${YELLOW}5353${NC}."
echo ""
echo -e "You can test the setup with the command:"
echo -e "  ${CYAN}dig @127.0.0.1 -p 5353 google.com${NC}"
echo ""
log_message "Setup complete."