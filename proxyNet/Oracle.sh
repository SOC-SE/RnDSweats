#!/bin/bash
# setup_wazuh_manager.sh
# Configures Oracle Linux 9.2 server to install Wazuh Manager, enable password $(head /dev/urandom | tr -dc A-Za-z0-9_ | head -c 24)authentication, and configure the firewall.
# Assumes running as root. Prioritizes speed and minimal changes.

set -e  # Exit on error
set -u  # Treat unset variables as error

# --- Variables ---
# Generate a secure, random password for agent registration
WAZUH_REGISTRATION_PASSWORD="Dkhfdas8210L:KJDf=0942q_*k13j*D*879414"

# --- Step 1: Update system and install dependencies ---
echo "INFO: Updating system and installing dependencies..."
dnf update -y
dnf install -y curl gnupg2 firewalld

# --- Step 2: Add Wazuh repository if not exists ---
if [ ! -f /etc/yum.repos.d/wazuh.repo ]; then
    echo "INFO: Adding Wazuh repository..."
    cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
protect=1
EOF
fi

# --- Step 3: Import GPG key if not already imported ---
if ! rpm -qa gpg-pubkey* | grep -q WAZUH; then
    echo "INFO: Importing Wazuh GPG key..."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
fi

# --- Step 4: Install wazuh-manager if not installed ---
if ! rpm -q wazuh-manager &> /dev/null; then
    echo "INFO: Installing wazuh-manager package..."
    dnf install -y wazuh-manager
fi

# --- Step 5: Enable Password Authentication ---
echo "INFO: Enabling password-based agent registration..."
# Use sed to insert the <auth> block into ossec.conf
sed -i '/<remote>/a \
  <auth>\
    <disabled>no</disabled>\
    <port>1515</port>\
    <use_source_ip>no</use_source_ip>\
    <password>'"${WAZUH_REGISTRATION_PASSWORD}"'</password>\
  </auth>' /var/ossec/etc/ossec.conf

# --- Step 6: Configure Firewall ---
echo "INFO: Configuring firewall rules..."
systemctl enable --now firewalld
firewall-cmd --permanent --add-port=1514/udp # Wazuh agent communication
firewall-cmd --permanent --add-port=1515/tcp # Wazuh agent registration
firewall-cmd --reload

# --- Step 7: Enable and start the service ---
echo "INFO: Starting Wazuh manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl restart wazuh-manager # Use restart to apply config changes

# --- Step 8: Verification and Password Display ---
if systemctl is-active --quiet wazuh-manager; then
    echo -e "\n Wazuh Manager installed and configured successfully."
    echo "🔑 Use this password in your agent deployment scripts:"
    echo "-----------------------------------------------------"
    echo "${WAZUH_REGISTRATION_PASSWORD}"
    echo "-----------------------------------------------------"
else
    echo "Error: Wazuh Manager service failed to start."
    exit 1
fi
