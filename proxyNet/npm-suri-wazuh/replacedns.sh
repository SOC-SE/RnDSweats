#!/bin/bash

# ==============================================================================
#           Disable systemd-resolved and Replace with dnsmasq
#
# This script automates the process of switching the system's DNS resolver
# from systemd-resolved to dnsmasq.
#
# It performs the following steps:
#   1. Checks for root privileges.
#   2. Disables and stops the systemd-resolved service.
#   3. Installs the dnsmasq package.
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


# --- Pre-flight Checks ---

# 1. Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root. Please use sudo." >&2
  exit 1
fi

set -e # Exit immediately if a command exits with a non-zero status.

# --- Step 1: Disable systemd-resolved ---

echo "--- Disabling and stopping systemd-resolved... ---"
systemctl disable systemd-resolved.service
systemctl stop systemd-resolved.service
echo "systemd-resolved has been disabled and stopped."
echo

# --- Step 2: Configure /etc/resolv.conf ---

RESOLV_CONF="/etc/resolv.conf"
echo "--- Configuring $RESOLV_CONF ---"

# Check if resolv.conf is a symlink managed by systemd-resolved
if [[ -L "$RESOLV_CONF" && "$(readlink -f "$RESOLV_CONF")" == */run/systemd/resolve/stub-resolv.conf ]]; then
    echo "Removing symlink at $RESOLV_CONF..."
    rm -f "$RESOLV_CONF"
else
    echo "Backing up existing $RESOLV_CONF to $RESOLV_CONF.bak..."
    if [ -f "$RESOLV_CONF" ]; then
        cp "$RESOLV_CONF" "$RESOLV_CONF.bak"
    fi
fi

# Create a new resolv.conf pointing to the local dnsmasq instance
echo "Creating new $RESOLV_CONF to use localhost (dnsmasq)..."
cat > "$RESOLV_CONF" << EOF
# This file is managed by your network configuration.
# Dnsmasq is handling DNS lookups.
nameserver 127.0.0.1
EOF
echo "$RESOLV_CONF configured successfully."
echo

# --- Step 3: Install dnsmasq ---

echo "--- Installing dnsmasq... ---"
# Update package lists and install dnsmasq
apt-get update
apt-get install -y dnsmasq
echo "dnsmasq has been installed."
echo

# --- Step 4: Configure dnsmasq ---

DNSMASQ_CONF="/etc/dnsmasq.conf"
echo "--- Configuring dnsmasq at $DNSMASQ_CONF ---"
echo "Backing up original config to $DNSMASQ_CONF.bak..."
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
echo "dnsmasq configured successfully."
echo

# --- Step 5: Start and Enable dnsmasq ---

echo "--- Starting and enabling dnsmasq service... ---"
systemctl enable dnsmasq.service
systemctl restart dnsmasq.service # Use restart to ensure it picks up the new config
echo "dnsmasq service has been enabled and started."
echo

# --- Final Verification ---

echo "--- Verifying DNS resolution... ---"
if nslookup example.com 127.0.0.1 > /dev/null; then
    echo "✅ Success! DNS resolution is working through dnsmasq."
    echo "Your system is now configured to use dnsmasq."
else
    echo "❌ Failure! DNS resolution test failed. Please check the configuration."
    echo "Check status with: systemctl status dnsmasq"
    echo "Check logs with: journalctl -u dnsmasq"
fi

exit 0

