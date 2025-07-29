#!/bin/bash
set -euo pipefail

# Add Wazuh repository (idempotent: check if exists)
if [ ! -f /etc/yum.repos.d/wazuh.repo ]; then
    curl -o /etc/yum.repos.d/wazuh.repo https://packages.wazuh.com/4.x/yum/wazuh.repo
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
fi

# Install wazuh-manager if not present
dnf install -y wazuh-manager || true  # Ignore if already installed

# Enable and start service (idempotent)
systemctl enable wazuh-manager
systemctl start wazuh-manager || systemctl restart wazuh-manager
