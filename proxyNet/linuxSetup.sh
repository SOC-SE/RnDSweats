#!/bin/bash
# ==============================================================================
# setup_linux_client.sh
#
# Configures Linux servers (CentOS/RHEL/Fedora, Debian/Ubuntu) to install
# and configure the Wazuh Agent.
#
# Usage:
# sudo ./setup_linux_client.sh
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error.
set -u

# --- Configuration ---
WAZUH_MANAGER_IP="172.20.241.20"

# --- Script Validation ---

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root. Please use sudo." >&2
  exit 1
fi

# --- Step 1: Detect distribution ---
echo "INFO: Detecting Linux distribution..."
if [ -f /etc/redhat-release ]; then
  DISTRO="rpm"
elif [ -f /etc/debian_version ]; then
  DISTRO="deb"
else
  echo "ERROR: Unsupported distribution. This script supports RPM (CentOS, RHEL, Fedora) and DEB (Debian, Ubuntu) based systems." >&2
  exit 1
fi
echo "INFO: Detected a $DISTRO-based system."


# --- Step 2: Install Wazuh Agent ---
echo "INFO: Installing and configuring Wazuh Agent..."

if [ "$DISTRO" == "rpm" ]; then
  # Install prerequisites
  yum install -y curl

  # Add the Wazuh repository
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

  # Install the agent with configuration
  WAZUH_MANAGER="$WAZUH_MANAGER_IP"  yum install -y wazuh-agent

elif [ "$DISTRO" == "deb" ]; then
  # Update package list and install prerequisites
  apt-get update -y
  apt-get install -y curl gnupg

  # Add the Wazuh repository using the recommended secure method
  install -m 0755 -d /etc/apt/keyrings
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /etc/apt/keyrings/wazuh.gpg
  echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

  # Update package list again with the new repo and install the agent
  apt-get update -y
  WAZUH_MANAGER="$WAZUH_MANAGER_IP"  apt-get install -y wazuh-agent
fi


# --- Step 3: Enable and Start the Agent ---
echo "INFO: Enabling and starting the Wazuh Agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Verify service status
systemctl status wazuh-agent --no-pager

echo "✅ INFO: Wazuh Agent installation and configuration complete."
echo "Script finished."
