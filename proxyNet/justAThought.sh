#!/bin/bash

# CCDC Development - Wazuh Manager & Dashboard Install for Oracle Linux 9 [FINAL v2]
# This script automates the full installation and configuration process:
# REVISION 2: Rebuilds dashboard config files instead of editing them to prevent path errors.
# ---
# IMPORTANT: Run this script with root privileges (e.g., using sudo).

# --- Configuration ---
# Your Splunk server's IP address.
SPLUNK_SERVER_IP="172.20.241.20"
# Port you will configure in Splunk to listen for these logs.
SPLUNK_LISTENING_PORT="9997"


# --- Pre-flight Check ---
echo ">>> [Step 1/6] Running network pre-flight check..."
if ! ping -c 1 -W 3 packages.wazuh.com &>/dev/null; then
  echo "!!! Network check failed: Could not resolve or reach packages.wazuh.com."
  echo "!!! Please fix your server's DNS configuration first."
  echo "!!! Try running: echo 'nameserver 172.20.242.200' | sudo tee /etc/resolv.conf"
  exit 1
fi
echo ">>> Network check passed."


# --- Main Execution ---

echo ">>> [Step 2/6] Adding the Wazuh YUM repository..."

if ! rpm -q gpg-pubkey-84827044-615b8a53 > /dev/null; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
fi

#Add the Wazuh mirror
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo

echo ">>> Repository added."

# ---

echo ">>> [Step 3/6] Installing Wazuh Manager and Dashboard..."

dnf clean all
dnf install -y wazuh-manager wazuh-dashboard

if [ $? -ne 0 ]; then
    echo "!!! Installation failed. Aborting."
    exit 1
fi

echo ">>> Packages installed."

# ---

echo ">>> [Step 4/6] Configuring Wazuh Services..."

# Configure Manager for Splunk Forwarding
MANAGER_CONFIG="/var/ossec/etc/ossec.conf"
cp $MANAGER_CONFIG ${MANAGER_CONFIG}.bak # Backup original config
if ! grep -q "<server>${SPLUNK_SERVER_IP}</server>" $MANAGER_CONFIG; then
    sed -i "s|</ossec_config>|  <syslog_output>\n    <server>${SPLUNK_SERVER_IP}</server>\n    <port>${SPLUNK_LISTENING_PORT}</port>\n    <format>json</format>\n  </syslog_output>\n\n</ossec_config>|" $MANAGER_CONFIG
    echo "--> Wazuh Manager configured for Splunk forwarding."
fi

# **REVISED SECTION:** Create dashboard configs directly to ensure they exist and are correct.

# 1. Create the Wazuh plugin configuration file.
# This tells the dashboard how to communicate with the Wazuh Manager API.
WAZUH_UI_CONFIG_PATH="/usr/share/wazuh-dashboard/data/wazuh/config"
mkdir -p "$WAZUH_UI_CONFIG_PATH"
chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/data
cat > ${WAZUH_UI_CONFIG_PATH}/wazuh.yml <<EOF
hosts:
  - id: default
    url: https://localhost
    port: 55000
    user: wazuh-wui
    password: wazuh-wui
EOF
echo "--> Wazuh Dashboard plugin config created."

# 2. Disable SSL in the main dashboard config file.
sed -i 's/server.ssl.enabled: true/server.ssl.enabled: false/' /etc/wazuh-dashboard/opensearch_dashboards.yml
echo "--> Wazuh Dashboard SSL disabled for HTTP access."


# ---

echo ">>> [Step 5/6] Enabling and starting services..."

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

# ---

echo ">>> [Step 6/6] Final Status Check..."
sleep 5 # Give services a moment to start up fully

echo "---"
echo "✅ Automation Complete!"
echo "---"
echo "Wazuh Manager Status: $(systemctl is-active wazuh-manager)"
echo "Wazuh Dashboard Status: $(systemctl is-active wazuh-dashboard)"
echo ""
echo "You can now access the Wazuh Dashboard at: http://<your-server-ip>:5601"
echo "Remember to configure the Splunk data input on port ${SPLUNK_LISTENING_PORT}."
