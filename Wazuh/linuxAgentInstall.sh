#!/bin/bash

# CCDC Development - Wazuh Agent Quick Deploy
# -------------------------------------------
# This script auto-detects the Linux distro family (Debian/Ubuntu vs. CentOS/Fedora)
# and installs the Wazuh agent, pointing it to our manager.
# Fast, simple, and gets the job done under pressure.

# --- CONFIGURATION ---
WAZUH_MANAGER_IP='172.20.241.20' # IP of the Splunk/Wazuh Manager server. 

# --- SCRIPT LOGIC ---
# Don't touch unless you know what you're doing.

# 1. Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. You are in a competition, you know the password." 
   exit 1
fi

echo "🚀 Starting Wazuh Agent deployment..."
echo "Manager IP is set to: ${WAZUH_MANAGER_IP}"

# 2. Detect Distro and Install Agent
if [ -f /etc/debian_version ]; then
    # Debian or Ubuntu
    echo "Detected Debian/Ubuntu system."
    export DEBIAN_FRONTEND=noninteractive
    
    echo "Updating package list..."
    apt-get update > /dev/null 2>&1
    
    echo "Installing dependencies..."
    apt-get install -y curl apt-transport-https gnupg > /dev/null 2>&1

    echo "Adding Wazuh repository..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    
    echo "Installing wazuh-agent..."
    apt-get update > /dev/null 2>&1
    apt-get install -y wazuh-agent > /dev/null 2>&1

elif [ -f /etc/redhat-release ]; then
    # CentOS or Fedora
    echo "Detected Red Hat-based system (CentOS/Fedora)."

    echo "Adding Wazuh repository..."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat <<EOF | tee /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

    echo "Installing wazuh-agent..."
    # Use dnf if available, otherwise yum. Fedora 21 has yum. 
    if command -v dnf &> /dev/null; then
        dnf install -y wazuh-agent > /dev/null 2>&1
    else
        yum install -y wazuh-agent > /dev/null 2>&1
    fi

else
    echo "Unsupported Linux distribution. Exiting."
    exit 1
fi

# 3. Configure Agent to Point to Manager
echo "Configuring agent to connect to ${WAZUH_MANAGER_IP}..."
sed -i "s/<address>MANAGER_IP<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/" /var/ossec/etc/ossec.conf

# 4. Enable and Start Service
echo "Enabling and starting the wazuh-agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "✅ Wazuh agent installation and configuration complete!"
echo "Run 'systemctl status wazuh-agent' to verify it's running."
echo "Check the Wazuh Dashboard to see if the agent has registered."
