#!/bin/bash
# setup_wazuh_manager.sh
# Configures Oracle Linux 9.2 server to install Wazuh Manager and enable the service.
# Assumes running as root. Prioritizes speed and minimal changes.

set -e  # Exit on error
set -u  # Treat unset variables as error

# Step 1: Update system and install dependencies
dnf update -y
dnf install -y curl gnupg2

# Step 2: Add Wazuh repository if not exists
if [ ! -f /etc/yum.repos.d/wazuh.repo ]; then
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

# Step 3: Import GPG key if not already imported
if ! rpm -qa gpg-pubkey* | grep -q WAZUH; then
    curl -o /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH https://packages.wazuh.com/key/GPG-KEY-WAZUH
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH
fi

# Step 4: Install wazuh-manager if not installed
if ! rpm -q wazuh-manager &> /dev/null; then
    dnf install -y wazuh-manager
fi

# Step 5: Enable and start the service
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Step 6: Basic verification
if systemctl is-active --quiet wazuh-manager; then
    echo "Wazuh Manager installed and enabled successfully."
else
    echo "Error: Wazuh Manager service failed to start."
    exit 1
fi
