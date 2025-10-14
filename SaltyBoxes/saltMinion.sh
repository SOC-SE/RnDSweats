#!/bin/bash


SCRIPT_TITLE="Salt Minion Universal Installer (Linux)"

echo "#####################################################"
echo "# $SCRIPT_TITLE #"
echo "#####################################################"

# --- Pre-Flight Checks ---

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

# Check for Debian/Ubuntu (apt)
if command -v apt &> /dev/null; then
    PKG_FAMILY="DEB"
    # Install curl explicitly, needed for the following commands
    PKG_INSTALL="apt update && apt install -y curl"
    
    # Commands confirmed to work for fetching key and sources list for Debian/Ubuntu
    REPO_COMMAND="mkdir -p /etc/apt/keyrings && curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null && curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.sources | tee /etc/apt/sources.list.d/salt.sources > /dev/null && apt update"
    
    echo 'Package: salt-*
Pin: version 3007.*
Pin-Priority: 1001' | sudo tee /etc/apt/preferences.d/salt-pin-1001

    MINION_PACKAGE="salt-minion"
    INSTALL_COMMAND="apt install -y $MINION_PACKAGE"
    echo "Detected Debian/Ubuntu system (Using apt)."

# Check for RHEL/CentOS (prefer DNF over YUM)
elif command -v dnf &> /dev/null; then
    PKG_FAMILY="RPM"
    # Install curl explicitly if not present
    PKG_INSTALL="dnf install -y curl"
    REPO_COMMAND="curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.repo | tee /etc/yum.repos.d/salt.repo > /dev/null"
    CLEAN_COMMAND="dnf clean expire-cache"
    MINION_PACKAGE="salt-minion"
    INSTALL_COMMAND="dnf install -y $MINION_PACKAGE"
    echo "Detected RHEL/Fedora system (Using dnf)."

# Check for RHEL/CentOS (use YUM fallback)
elif command -v yum &> /dev/null; then
    PKG_FAMILY="RPM"
    # Install curl explicitly if not present
    PKG_INSTALL="yum install -y curl"
    REPO_COMMAND="curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.repo | tee /etc/yum.repos.d/salt.repo > /dev/null"
    CLEAN_COMMAND="yum clean expire-cache"
    MINION_PACKAGE="salt-minion"
    INSTALL_COMMAND="yum install -y $MINION_PACKAGE"
    echo "Detected RHEL/CentOS system (Using yum)."

else
    echo "Error: Cannot determine package manager (apt, dnf, or yum). Exiting."
    exit 1
fi

# --- Installation Logic ---

echo "--- Installing curl and checking prerequisites ---"
# Install curl first, needed for the repository step
eval $PKG_INSTALL || { echo "Error: Failed to install prerequisite packages. Check network connectivity or package sources."; exit 1; }

echo "--- Installing Salt Repository ---"
# We run the commands directly without 'sudo' as the script checked for root privileges
# Note: The REPO_COMMAND includes 'apt update' for DEB systems to refresh after adding the repo.
eval $REPO_COMMAND || { echo "Error: Failed to set up Salt repository. Exiting. Check DNS resolution for repo.saltproject.io."; exit 1; }

# RHEL-specific cleanup
if [ "$PKG_FAMILY" == "RPM" ]; then
    echo "Cleaning package cache..."
    eval $CLEAN_COMMAND
fi

echo "--- Installing $MINION_PACKAGE ---"
# Run the final minion install command
eval $INSTALL_COMMAND

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

# Start and enable the minion service
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
