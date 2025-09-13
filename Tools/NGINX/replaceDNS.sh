#!/bin/bash

# ==============================================================================
#           Disable systemd-resolved and Replace with dnsmasq
#
# This script automates the process of switching the system's DNS resolver
# from systemd-resolved to dnsmasq.
#
# It performs the following steps:
#   1. Checks for root privileges.
#   2. Installs the dnsmasq package.
#   3. Disables and stops the systemd-resolved service.
#   4. Reconfigures /etc/resolv.conf to point to the local dnsmasq server.
#   5. Creates a basic, functional configuration for dnsmasq.
#   6. Enables and starts the dnsmasq service.
#
# Compatibility: Designed for Debian/Ubuntu-based systems.
# ==============================================================================

# --- Configuration ---
# You can change these upstream DNS servers if you prefer others.
# Examples:
#   Cloudflare: 1.1.1.1, 1.0.0.1
#   Google:     8.8.8.8, 8.8.4.4
#   OpenDNS:    208.67.222.222, 208.67.220.220
UPSTREAM_DNS_1="1.1.1.1"
UPSTREAM_DNS_2="1.0.0.1"

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

# --- Pre-flight Checks ---

# 1. Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root. Please use sudo."
  exit 1
fi

set -e # Exit immediately if a command exits with a non-zero status.

# --- Step 1: Detect Distro and Install Packages ---

log_message "Detecting distribution and installing packages..."
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

# Install dnsmasq and dnsutils (for nslookup)
$PKG_MANAGER install -y dnsmasq dnsutils

# --- Step 2: Disable systemd-resolved ---

log_message "Disabling and stopping systemd-resolved..."
if systemctl is-active --quiet systemd-resolved; then
    systemctl disable systemd-resolved.service
    systemctl stop systemd-resolved.service
    log_message "systemd-resolved has been disabled and stopped."
else
    log_message "systemd-resolved is not running. Skipping."
fi

# --- Step 3: Configure /etc/resolv.conf ---

RESOLV_CONF="/etc/resolv.conf"
echo "--- Configuring $RESOLV_CONF ---"

# Check if resolv.conf is a symlink managed by systemd-resolved
if [ -L "$RESOLV_CONF" ]; then
    log_message "Removing symlink at $RESOLV_CONF..."
    rm -f "$RESOLV_CONF"
else
    log_message "Backing up existing $RESOLV_CONF to $RESOLV_CONF.bak..."
    if [ -f "$RESOLV_CONF" ]; then
        cp "$RESOLV_CONF" "$RESOLV_CONF.bak"
    fi
fi

# Create a new resolv.conf pointing to the local dnsmasq instance
log_message "Creating new $RESOLV_CONF to use localhost (dnsmasq)..."
cat > "$RESOLV_CONF" << EOF
# This file is managed by your network configuration.
# Dnsmasq is handling DNS lookups.
nameserver 127.0.0.1
EOF
log_message "$RESOLV_CONF configured successfully."

# --- Step 4: Configure dnsmasq ---

DNSMASQ_CONF="/etc/dnsmasq.conf"
log_message "Configuring dnsmasq at $DNSMASQ_CONF..."
log_message "Backing up original config to $DNSMASQ_CONF.bak..."
if [ -f "$DNSMASQ_CONF" ]; then
    mv "$DNSMASQ_CONF" "$DNSMASQ_CONF.bak"
fi

echo "Creating new dnsmasq configuration..."
cat > "$DNSMASQ_CONF" << EOF
# Listen on the local loopback interface only.
listen-address=127.0.0.1

# Do not use /etc/resolv.conf to find upstream servers.
no-resolv

# Specify upstream DNS servers directly.
server=${UPSTREAM_DNS_1}
server=${UPSTREAM_DNS_2}

EOF
log_message "dnsmasq configured successfully."

# --- Step 5: Start and Enable dnsmasq ---

log_message "Starting and enabling dnsmasq service..."
systemctl enable dnsmasq.service
systemctl restart dnsmasq.service # Use restart to ensure it picks up the new config
log_message "dnsmasq service has been enabled and started."

# --- Final Verification ---

log_message "Verifying DNS resolution..."
if nslookup example.com 127.0.0.1 > /dev/null; then
    log_message "✅ Success! DNS resolution is working through dnsmasq."
else
    log_warning "❌ Failure! DNS resolution test failed. Please check the configuration."
    log_warning "Check status with: systemctl status dnsmasq"
    log_warning "Check logs with: journalctl -u dnsmasq"
fi

exit 0
