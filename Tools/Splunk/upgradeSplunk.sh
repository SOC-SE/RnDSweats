#!/bin/bash
#
#  A script to automate upgrading Splunk during competition.
#  Not super complicated. Much nicer than most of my other Splunk scripts, this one doesn't need to be so flexible.
#
#  As of three competitions, it works well!
#
#  Samuel Brucker 2024-2025

#Set the variable for the download URL
SPLUNK_VERSION="10.0.1"
SPLUNK_BUILD="ea5bfadeac3a"
SPLUNK_PACKAGE_RPM="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PACKAGE_RPM}"

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo privileges"
    exit 1
fi

# Set Splunk home path - adjust if your Splunk installation is elsewhere
SPLUNK_HOME=/opt/splunk

# Download latest Enterprise version (adjust URL based on your needs)
if ! wget -q --show-progress "$SPLUNK_DOWNLOAD_URL" -O splunk-upgrade.rpm; then
    echo "Splunk's upgrade failed to download"
    exit 1
fi

# Stop Splunk first
echo "Stopping Splunk..."
"$SPLUNK_HOME/bin/splunk" stop

# Backup current installation
BACKUP_DIR="/tmp/splunk_backup_pre-update_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -rp "$SPLUNK_HOME/etc" "$BACKUP_DIR/"
cp -rp "$SPLUNK_HOME/var/log" "$BACKUP_DIR/"

if ! rpm -Uhv splunk-*.rpm; then
    echo "Upgrade installation failed"
    exit 1
fi

# Initialize upgrade
"$SPLUNK_HOME/bin/splunk" _internal restart

# Start Splunk
echo "Starting Splunk..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes

# Clean up downloaded package
rm -f splunk-*.rpm