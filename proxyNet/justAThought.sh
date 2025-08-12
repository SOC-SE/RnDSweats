#!/bin/bash

# CCDC Development - Wazuh Manager & Dashboard Install for Oracle Linux 9 [REVISED]
# This script installs the Wazuh manager and dashboard and configures log
# forwarding to Splunk.
# REVISION: Corrected repo URL and added a network pre-flight check.
# ---
# IMPORTANT: Run this script with root privileges (e.g., using sudo).

# --- Configuration ---
# CHANGE THIS to your Splunk server's IP address. From the topology, this is the default.
SPLUNK_SERVER_IP="172.20.241.20" # [cite: 504]
# Port you will configure in Splunk to listen for these logs.
SPLUNK_LISTENING_PORT="9997"


# --- Pre-flight Check ---
echo ">>> [Step 0/6] Running network pre-flight check..."
if ! ping -c 1 -W 3 packages.wazuh.com &>/dev/null; then
  echo "!!! Network check failed: Could not resolve or reach packages.wazuh.com."
  echo "!!! Please fix your server's DNS configuration first."
  echo "!!! Try running: echo 'nameserver 172.20.242.200' | sudo tee /etc/resolv.conf"
  exit 1
fi
echo ">>> Network check passed."


# --- Main Execution ---

echo ">>> [Step 1/6] Adding the Wazuh YUM repository..."

if ! rpm -q gpg-pubkey-84827044-615b8a53 > /dev/null; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
fi

# CORRECTED REPO URL: Wazuh consolidated their EL9 repo path.
cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

echo ">>> Repository added."

# ---

echo ">>> [Step 2/6] Installing Wazuh Manager and Dashboard..."

dnf clean all
dnf install -y wazuh-manager wazuh-dashboard

if [ $? -ne 0 ]; then
    echo "!!! Installation failed. Aborting."
    exit 1
fi

echo ">>> Packages installed."

# ---

echo ">>> [Step 3/6] Configuring Wazuh Manager (ossec.conf) for Splunk forwarding..."

MANAGER_CONFIG="/var/ossec/etc/ossec.conf"

# Create a backup of the original config, just in case.
cp $MANAGER_CONFIG ${MANAGER_CONFIG}.bak

if ! grep -q "<server>${SPLUNK_SERVER_IP}</server>" $MANAGER_CONFIG; then
    sed -i "s|</ossec_config>|  <syslog_output>\n    <server>${SPLUNK_SERVER_IP}</server>\n    <port>${SPLUNK_LISTENING_PORT}</port>\n    <format>json</format>\n  </syslog_output>\n\n</ossec_config>|" $MANAGER_CONFIG
    echo ">>> ossec.conf updated for Splunk."
else
    echo ">>> Splunk forwarding configuration already seems to exist. Skipping."
fi


# ---

echo ">>> [Step 4/6] Configuring Wazuh Dashboard..."
sed -i 's/url: https:\/\/localhost:55000/url: http:\/\/localhost:55000/' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
echo ">>> Dashboard configured."

# ---

echo ">>> [Step 5/6] Enabling and starting services..."

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

# ---

echo ">>> [Step 6/6] Final Status Check..."
echo "---"
echo "✅ Installation and Configuration Complete!"
echo "---"
echo "Wazuh Manager Status:"
systemctl is-active wazuh-manager
echo "Wazuh Dashboard Status:"
systemctl is-active wazuh-dashboard
echo ""
echo "Next Steps:"
echo "1. On your Splunk Server (${SPLUNK_SERVER_IP}), set up a TCP or UDP data input on port ${SPLUNK_LISTENING_PORT}."
echo "2. Set the Splunk source type to 'wazuh_json' for automatic parsing (requires the Wazuh Splunk App)."
echo "3. Access the Wazuh Dashboard at http://<your-server-ip>:5601"
echo "4. Use '/var/ossec/bin/manage_agents' on this server to add and extract keys for your agents."
