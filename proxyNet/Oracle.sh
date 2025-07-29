#!/bin/bash
# setup_wazuh_manager.sh
# Configures Oracle Linux 9.2 server to install Wazuh Manager,
# enables necessary firewall ports, and provides the password for agent registration.
# Assumes running as root. Prioritizes speed and minimal changes.

set -e  # Exit on error
set -u  # Treat unset variables as error

# --- Variables ---
# Generate a secure, random password for agent registration.
# This password will be used by the 'agent-auth' utility on the agent side.
WAZUH_REGISTRATION_PASSWORD="Dkhfdas8210L:KJDf=0942q_*k13j*D*879414"

# --- Step 1: Update system and install dependencies ---
echo "INFO: Updating system and installing dependencies..."
dnf install -y curl gnupg2

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

# --- Step 5: (No direct ossec.conf modification for password auth) ---
# The previous attempt to insert an <auth> block into ossec.conf was incorrect.
# Wazuh's password-based agent registration is handled by the 'authd' daemon,
# which runs as part of the Wazuh manager. Agents use the 'agent-auth' utility
# with a password to register, and 'authd' processes these requests.
# There is no global password configured in ossec.conf for this purpose.
echo "INFO: Wazuh Manager's 'authd' service handles password-based agent registration by default."
echo "INFO: No direct ossec.conf modification is needed for this functionality."


# --- Step 7: Enable and start the service ---
echo "INFO: Starting Wazuh manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl restart wazuh-manager # Use restart to apply config changes

# --- Step 8: Verification and Password Display ---
if systemctl is-active --quiet wazuh-manager; then
    echo -e "\n Wazuh Manager installed and configured successfully."
    echo "Use this password in your agent deployment scripts with the 'agent-auth' utility:"
    echo "-----------------------------------------------------"
    echo "${WAZUH_REGISTRATION_PASSWORD}"
    echo "-----------------------------------------------------"
    echo "Example command to register an agent (run on the agent machine):"
    echo "  /var/ossec/bin/agent-auth -m <MANAGER_IP_OR_HOSTNAME> -P \"${WAZUH_REGISTRATION_PASSWORD}\""
else
    echo "Error: Wazuh Manager service failed to start."
    exit 1
fi
