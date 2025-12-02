#!/bin/bash

# ==============================================================================
# Salt Minion Universal Installer (Linux) - Revised
# Targets: Debian/Ubuntu & RHEL/CentOS/Rocky/Alma
# Version: Salt 3007 LTS (Unified)
# ==============================================================================

SCRIPT_TITLE="Salt Minion Universal Installer"
DEFAULT_MASTER_IP="172.20.242.20"

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

echo "#####################################################"
echo "# $SCRIPT_TITLE #"
echo "#####################################################"

# --- 1. Pre-Flight Checks ---

if [ "$EUID" -ne 0 ]; then
    error "This script must be run with root privileges. Try: sudo ./saltMinionLinux.sh"
fi

# --- 2. User Input ---

# Prompt for Salt Master IP with Default
read -p "Enter Salt Master IP [Default: $DEFAULT_MASTER_IP]: " INPUT_IP
SALT_MASTER_IP=${INPUT_IP:-$DEFAULT_MASTER_IP}
log "Using Master IP: $SALT_MASTER_IP"

# Prompt for Minion ID
read -p "Enter a unique Minion ID (Press ENTER to use system hostname): " MINION_ID
if [ -z "$MINION_ID" ]; then
    MINION_ID=$(hostname -f)
fi
log "Using Minion ID: $MINION_ID"

# --- 3. OS Detection & Repo Setup (Unified to 3007) ---

log "Detecting OS and configuring repositories..."

if command -v apt-get &> /dev/null; then
    # --- Debian / Ubuntu ---
    PKG_FAMILY="DEB"
    PKG_MGR="apt-get"
    
    # Install prerequisites
    $PKG_MGR update -y > /dev/null
    $PKG_MGR install -y curl gnupg2 > /dev/null

    # Setup Keyrings
    mkdir -p /etc/apt/keyrings
    
    # Download Salt 3007 Signing Key
    curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null
    
    # Create Sources List (Hardcoded to 3007 LTS to ensure version match with RHEL)
    # We create the file manually to ensure it points to the correct architecture and release
    ARCH=$(dpkg --print-architecture)
    CODENAME=$(lsb_release -cs 2>/dev/null || cat /etc/os-release | grep VERSION_CODENAME | cut -d= -f2)
    
    if [ -z "$CODENAME" ]; then error "Could not detect OS Codename."; fi

    echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.pgp arch=$ARCH] https://packages.broadcom.com/artifactory/saltproject-deb/ stable/3007 $CODENAME main" | tee /etc/apt/sources.list.d/salt.list > /dev/null
    
    # Pinning priority to ensure we prefer this repo
    cat <<EOF > /etc/apt/preferences.d/salt-pin-1001
Package: salt-*
Pin: origin packages.broadcom.com
Pin-Priority: 1001
EOF

    $PKG_MGR update -y
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    # --- RHEL / CentOS / Rocky / Alma ---
    PKG_FAMILY="RPM"
    if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
    
    # Detect RHEL Version (7, 8, 9)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        EL_VERSION=$(echo $VERSION_ID | cut -d. -f1)
    else
        EL_VERSION=$(rpm -E %rhel)
    fi
    
    log "Detected RHEL/EL Version: $EL_VERSION"
    
    # Install Salt 3007 Repo RPM specifically
    REPO_URL="https://repo.saltproject.io/salt/py3/redhat/salt-repo-3007.el${EL_VERSION}.noarch.rpm"
    
    log "Installing Repo RPM from: $REPO_URL"
    $PKG_MGR install -y "$REPO_URL"
    
    $PKG_MGR clean expire-cache
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

else
    error "Unsupported Package Manager. Only apt, dnf, and yum are supported."
fi

# --- 4. Installation ---

log "Installing Salt Minion package..."
eval $INSTALL_CMD || error "Failed to install salt-minion."

# --- 5. Service Handling (The Ubuntu Fix) ---

log "Stopping service for configuration..."
# STOP the service immediately. This prevents the "start failure" loop on Ubuntu
# that happens when the package starts with an unconfigured master.
systemctl stop salt-minion
systemctl disable salt-minion 2>/dev/null || true

# --- 6. Configuration ---

log "Configuring /etc/salt/minion.d/master.conf..."
mkdir -p /etc/salt/minion.d
echo "master: $SALT_MASTER_IP" > /etc/salt/minion.d/master.conf

log "Setting Minion ID to $MINION_ID..."
echo "$MINION_ID" > /etc/salt/minion_id

# --- 7. Service Start & Verification ---

log "Enabling and Starting Salt Minion..."
systemctl enable salt-minion
systemctl start salt-minion

# Wait for potential first-start failure or initialization
log "Waiting for service initialization (5s)..."
sleep 5

# The "Double Restart" Fix
# Ubuntu minions often fail the first bind or DNS lookup if network isn't fully ready
# or if the package install started a rogue process. We explicitly restart now.
log "Performing stability restart..."
systemctl restart salt-minion

# Verify Status
if systemctl is-active --quiet salt-minion; then
    log "Service is ACTIVE."
else
    warn "Service is not active yet. Retrying one last time..."
    sleep 5
    systemctl restart salt-minion
    if systemctl is-active --quiet salt-minion; then
        log "Service is ACTIVE after retry."
    else
        # Don't exit, just warn, so we can still copy tools
        warn "Service failed to start. Check 'systemctl status salt-minion' manually."
    fi
fi

# --- 8. Post-Install Tasks ---

if [ -d "../Tools" ]; then
    log "Copying tools to /etc/runtl..."
    mkdir -p /etc/runtl
    cp -r ../Tools/* /etc/runtl/
else
    warn "../Tools directory not found. Skipping tool copy."
fi

echo ""
echo "#####################################################"
echo "# MINION SETUP COMPLETE" 
echo "#####################################################"
echo "Minion ID: $MINION_ID"
echo "Master IP: $SALT_MASTER_IP"
echo "Version:   Salt 3007 (LTS)"
echo "Status:    $(systemctl is-active salt-minion)"
echo "#####################################################"