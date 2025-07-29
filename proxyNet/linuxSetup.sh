#!/bin/bash
# setup_linux_client.sh
# EDITED: Uses apt-key add for Debian systems to ensure GPG key is trusted.
# Configures Linux servers (CentOS 7, Fedora 21, Debian 10) to install Wazuh Agent, point to manager, and change default gateway.
# Assumes running as root. Detects distro and handles accordingly. Prioritizes speed and uptime.

set -e  # Exit on error
set -u  # Treat unset variables as error

# --- Variables ---
WAZUH_MANAGER_IP="172.20.241.20"
NEW_GATEWAY_IP="172.20.242.10"

# --- Step 1: Detect distribution and version ---
if [ -f /etc/redhat-release ]; then
    DISTRO="rpm"  # CentOS or Fedora (yum-based)
    if grep -q "Fedora" /etc/redhat-release; then
        FEDORA_VERSION=$(awk '{print $3}' /etc/fedora-release)
        if [ "$FEDORA_VERSION" -lt 22 ]; then
            echo "Warning: Fedora version $FEDORA_VERSION is not supported by Wazuh (requires 22+). Skipping Wazuh installation, but proceeding with gateway change."
            SKIP_WAZUH=true
        else
            SKIP_WAZUH=false
        fi
    else
        SKIP_WAZUH=false
    fi
elif [ -f /etc/debian_version ]; then
    DISTRO="deb"  # Debian
    SKIP_WAZUH=false
else
    echo "Unsupported distribution. Exiting."
    exit 1
fi

# --- Step 2: Update system and install prerequisites ---
echo "INFO: Updating system and installing prerequisites..."
if [ "$DISTRO" == "rpm" ]; then
    yum update -y
    yum install -y curl
elif [ "$DISTRO" == "deb" ]; then
    apt-get update -y
    apt-get install -y curl gnupg
fi

# --- Step 3: Add Wazuh repository and install agent (if not skipped) ---
if [ "${SKIP_WAZUH:-false}" != "true" ]; then
    echo "INFO: Installing Wazuh Agent..."
    if [ "$DISTRO" == "rpm" ]; then
        if [ ! -f /etc/yum.repos.d/wazuh.repo ]; then
            cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
        fi
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        yum install -y wazuh-agent
    elif [ "$DISTRO" == "deb" ]; then
        # On older Debian systems, directly adding the key with apt-key is more reliable.
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        # Create the repository file without the 'signed-by' attribute.
        echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
        apt-get update -y
        apt-get install -y wazuh-agent
    fi

# --- Step 4: Configure Wazuh agent to point to manager ---
    echo "INFO: Configuring Wazuh agent..."
    sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/g" /var/ossec/etc/os
