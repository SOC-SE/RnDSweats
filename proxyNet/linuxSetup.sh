#!/bin/bash
# setup_linux_client.sh
# EDITED: Removed incorrect gateway-changing logic. Egress filtering must be done on the Palo Alto firewall.
# Configures Linux servers (CentOS 7, Fedora 21, Debian 10) to install and configure the Wazuh Agent.
# Assumes running as root. Detects distro and handles accordingly.

set -e  # Exit on error
set -u  # Treat unset variables as error

# --- Variables ---
WAZUH_MANAGER_IP="172.20.241.20"

# --- Step 1: Detect distribution and version ---
if [ -f /etc/redhat-release ]; then
    DISTRO="rpm"  # CentOS or Fedora (yum-based)
    if grep -q "Fedora" /etc/redhat-release; then
        FEDORA_VERSION=$(awk '{print $3}' /etc/fedora-release)
        if [ "$FEDORA_VERSION" -lt 22 ]; then
            echo "Warning: Fedora version $FEDORA_VERSION is not supported by Wazuh (requires 22+). Skipping Wazuh installation."
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

# --- Step 3: Install and Configure Wazuh Agent (if not skipped) ---
if [ "${SKIP_WAZUH:-false}" != "true" ]; then
    echo "INFO: Installing and configuring Wazuh Agent..."
    if [ "$DISTRO" == "rpm" ]; then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
        yum install -y wazuh-agent
    elif [ "$DISTRO" == "deb" ];
        # On older Debian systems, directly adding the key with apt-key is more reliable.
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
        apt-get update -y
        apt-get install wazuh-agent -y
    fi
    
    # Configure agent to point to manager
    sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/g" /var/ossec/etc/ossec.conf

    # Enable and start service
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    echo "INFO: Wazuh Agent installed and started."
else
    echo "INFO: Wazuh installation skipped due to unsupported OS version."
fi

echo "Script finished."
