#!/bin/bash

# Define the installation script title
SCRIPT_TITLE="Salt Minion Universal Installer (Debian/RHEL)"

echo "#####################################################"
echo "# $SCRIPT_TITLE #"
echo "#####################################################"

# --- 1. Get User Input ---

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

# --- 2. Detect OS Family ---

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
else
    echo "Error: Cannot determine OS. The /etc/os-release file is missing."
    exit 1
fi

# Convert ID to lowercase for robust comparison
OS_ID_LOWER=$(echo "$OS_ID" | tr '[:upper:]' '[:lower:]')

echo "Detected OS ID: $OS_ID_LOWER"

# --- 3. Installation Logic ---

if [[ "$OS_ID_LOWER" == "ubuntu" || "$OS_ID_LOWER" == "debian" ]]; then
    
    # === Debian/Ubuntu Installation Logic ===
    echo "--- Installing Salt Minion for Debian-based system (apt) ---"
    
    # Determine the release codename
    if [ "$VERSION_CODENAME" == "bionic" ]; then
        # Ubuntu 18.04
        RELEASE_DIR="18.04"
        DISTRO_CODENAME="bionic"
    elif [ "$VERSION_CODENAME" == "focal" ]; then
        # Ubuntu 20.04
        RELEASE_DIR="20.04"
        DISTRO_CODENAME="focal"
    else
        # Use latest for newer releases, relying on the system's version
        echo "Warning: Using latest package repo, adjust manually if issues occur."
        RELEASE_DIR="$VERSION_ID"
        DISTRO_CODENAME="$VERSION_CODENAME"
    fi

    # 1. Update package list
    sudo apt update
    
    # 2. Install dependencies for HTTPS and keys
    sudo apt install -y curl gnupg apt-transport-https

    # 3. Add Salt Project repository key
    echo "Adding Salt Project GPG key..."
    sudo curl -fsSL -o /usr/share/keyrings/salt-archive-keyring.gpg "https://repo.saltproject.io/py3/$OS_ID_LOWER/$RELEASE_DIR/amd64/latest/salt-archive-keyring.gpg"
    
    # 4. Add the repository
    echo "Adding Salt repository to sources.list.d..."
    echo "deb [signed-by=/usr/share/keyrings/salt-archive-keyring.gpg arch=amd64] https://repo.saltproject.io/py3/$OS_ID_LOWER/$RELEASE_DIR/amd64/latest $DISTRO_CODENAME main" | sudo tee /etc/apt/sources.list.d/salt.list > /dev/null

    # 5. Install the minion package
    sudo apt update
    sudo apt install -y salt-minion

elif [[ "$OS_ID_LOWER" == "centos" || "$OS_ID_LOWER" == "rhel" || "$OS_ID_LOWER" == "redhat" ]]; then

    # === RHEL/CentOS Installation Logic (Updated for Robustness) ===
    echo "--- Installing Salt Minion for RHEL-based system (yum/dnf) ---"

    # Use yum for CentOS 7, dnf for newer RHEL 8/9
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
        RELEASE_VERSION="el$VERSION_ID"
        CLEAN_CMD="sudo dnf clean expire-cache"
        INSTALL_CMD="sudo dnf install -y"
    else
        PACKAGE_MANAGER="yum"
        RELEASE_VERSION="el7" # Assuming CentOS 7 or older RHEL
        CLEAN_CMD="sudo yum clean expire-cache"
        INSTALL_CMD="sudo yum install -y"
    fi

    REPO_RPM_URL="https://repo.saltproject.io/py3/redhat/salt-py3-repo-latest.$RELEASE_VERSION.noarch.rpm"
    REPO_RPM_FILENAME="salt-repo-latest.rpm"

    # 1. Download the Salt Project repository package (Python 3) using curl
    echo "Downloading Salt Project repository package ($PACKAGE_MANAGER) from $REPO_RPM_URL..."
    # Ensure curl is installed first
    $INSTALL_CMD curl
    
    sudo curl -L -o /tmp/$REPO_RPM_FILENAME $REPO_RPM_URL

    if [ $? -ne 0 ]; then
        echo "Error: Failed to download the Salt repository RPM. Check network connectivity or proxy settings on the CentOS host."
        exit 1
    fi
    
    # Install the downloaded RPM using rpm (more reliable than yum install <URL>)
    echo "Installing repository RPM..."
    sudo rpm -Uvh /tmp/$REPO_RPM_FILENAME

    # 2. Clean cache and install salt-minion
    $CLEAN_CMD
    $INSTALL_CMD salt-minion

else
    echo "Error: Unsupported OS family ($OS_ID). Exiting."
    exit 1
fi

# --- 4. Configuration (Universal) ---

echo "--- Configuring Minion Connection ---"

# Ensure the minion.d directory exists
sudo mkdir -p /etc/salt/minion.d

# Create a master configuration file
echo "Configuring Master IP: $SALT_MASTER_IP"
echo "master: $SALT_MASTER_IP" | sudo tee /etc/salt/minion.d/master.conf > /dev/null

# Set the Minion ID explicitly
echo "Setting Minion ID: $MINION_ID"
echo "$MINION_ID" | sudo tee /etc/salt/minion_id > /dev/null

# 5. Start and enable the minion service
echo "Starting and enabling salt-minion service..."
# Use conditional execution based on command success for robustness
if ! sudo systemctl enable salt-minion; then
    echo "Warning: Could not enable salt-minion service. It may not be installed or configured correctly."
    # Attempt to start anyway
fi
sudo systemctl restart salt-minion

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
