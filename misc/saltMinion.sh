#!/bin/bash

# Define the installation script title
SCRIPT_TITLE="Salt Minion Universal Installer (Linux)"

echo "#####################################################"
echo "# $SCRIPT_TITLE #"
echo "#####################################################"

# --- 0. Pre-Flight Checks ---

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run with root privileges."
    echo "Please run again using 'sudo ./install_minion.sh'"
    exit 1
fi

# --- Get User Input ---

# Prompt for Salt Master IP (Mandatory)
read -p "Enter the Salt Master IP address (e.g., 192.168.1.100): " SALT_MASTER_IP

if [ -z "$SALT_MASTER_IP" ]; then
    echo "Error: Salt Master IP address is mandatory. Exiting."
    exit 1
fi

# Prompt for Minion ID (Optional)
read -p "Enter a unique Minion ID (Press ENTER to use system hostname): " MINION_ID

# If MINION_ID is empty, Salt will default to the system's FQDN/hostname
if [ -z "$MINION_ID" ]; then
    MINION_ID=$(hostname -f)
    echo "Using default Minion ID: $MINION_ID"
fi

# --- OS and Package Manager Detection ---

# Check for Debian/Ubuntu
if command -v apt &> /dev/null; then
    PKG_FAMILY="DEB"
    # Install curl as part of the initial command chain if needed
    PKG_INSTALL="apt update && apt install -y curl" 
    # Curl is needed for REPO_COMMAND, so ensure it runs first
    REPO_COMMAND="curl -fsSL https://repo.saltproject.io/salt/py3/ubuntu/20.04/amd64/latest/salt-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/salt-archive-keyring.gpg && echo 'deb [signed-by=/usr/share/keyrings/salt-archive-keyring.gpg arch=amd64] https://repo.saltproject.io/salt/py3/ubuntu/20.04/amd64/latest focal main' | tee /etc/apt/sources.list.d/salt.list > /dev/null && apt update"
    MINION_PACKAGE="salt-minion"
    echo "Detected Debian/Ubuntu system (Using apt)."

# Check for RHEL (prefer DNF over YUM)
elif command -v dnf &> /dev/null; then
    PKG_FAMILY="RPM"
    # Install curl explicitly if not present
    PKG_INSTALL="dnf install -y curl"
    REPO_COMMAND="curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.repo | tee /etc/yum.repos.d/salt.repo > /dev/null"
    CLEAN_COMMAND="dnf clean expire-cache"
    MINION_PACKAGE="salt-minion"
    echo "Detected RHEL/Fedora system (Using dnf)."

# Check for RHEL (use YUM fallback)
elif command -v yum &> /dev/null; then
    PKG_FAMILY="RPM"
    # Install curl explicitly if not present
    PKG_INSTALL="yum install -y curl"
    REPO_COMMAND="curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.repo | tee /etc/yum.repos.d/salt.repo > /dev/null"
    CLEAN_COMMAND="yum clean expire-cache"
    MINION_PACKAGE="salt-minion"
    echo "Detected RHEL system (Using yum)."

else
    echo "Error: Cannot determine package manager (apt, dnf, or yum). Exiting."
    exit 1
fi

# --- Installation Logic ---

echo "--- Installing curl and checking prerequisites ---"
# Install curl first, needed for the repository step
eval $PKG_INSTALL || { echo "Error: Failed to install curl. Check network connectivity or package sources."; exit 1; }

echo "--- Installing Salt Repository ---"
# We run the commands directly without 'sudo' as the script checked for root privileges
eval $REPO_COMMAND || { echo "Error: Failed to set up Salt repository. Exiting."; exit 1; }

# RHEL-specific cleanup
if [ "$PKG_FAMILY" == "RPM" ]; then
    echo "Cleaning package cache..."
    eval $CLEAN_COMMAND
fi

echo "--- Installing $MINION_PACKAGE ---"
# Run the final minion install command
if [ "$PKG_FAMILY" == "DEB" ]; then
    # For Debian/Ubuntu, we run apt install again specifically for the minion package
    apt install -y $MINION_PACKAGE
else
    # For RHEL/CentOS, yum/dnf install the minion package
    eval "$PKG_INSTALL $MINION_PACKAGE"
fi

if [ $? -ne 0 ]; then
    echo "Error: Failed to install $MINION_PACKAGE. Exiting."; exit 1;
fi


# --- Configuration (Universal) ---

echo "--- Configuring Minion Connection ---"

# Ensure the minion.d directory exists
mkdir -p /etc/salt/minion.d

# Create a master configuration file
echo "Configuring Master IP: $SALT_MASTER_IP"
echo "master: $SALT_MASTER_IP" | tee /etc/salt/minion.d/master.conf > /dev/null

# Set the Minion ID explicitly
echo "Setting Minion ID: $MINION_ID"
echo "$MINION_ID" | tee /etc/salt/minion_id > /dev/null

# 5. Start and enable the minion service
echo "Starting and enabling salt-minion service..."
systemctl enable salt-minion
systemctl restart salt-minion

echo "#####################################################"
echo "# MINION SETUP COMPLETE #"
echo "#####################################################"
echo "Minion ID: $MINION_ID"
echo "Master IP: $SALT_MASTER_IP"
echo ""
echo "NEXT STEP: On your Salt Master, run the following commands:"
echo "1. List pending keys:"
echo "   sudo salt-key -L"
echo "2. Accept the new minion key (replace <MINION_ID>):"
echo "   sudo salt-key -a $MINION_ID"
echo "3. Verify the connection:"
echo "   sudo salt '$MINION_ID' test.ping"
