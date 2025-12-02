#!/bin/bash

# ==============================================================================
# Salt Minion Manual Installer (Universal SHA-1 Fix Edition)
# Targets: Salt 3007 LTS
# ==============================================================================
#
#   Installation script to install the Salt Minion on most RHEL-like and Debian-like machines.
#
#   Samuel Brucker 2025-2026
#

SCRIPT_TITLE="S"
DEFAULT_MASTER_IP="172.20.242.20"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

echo "#####################################################"
echo "# Salt Minion  Installer #"
echo "#####################################################"

if [ "$EUID" -ne 0 ]; then
    error "This script must be run with root privileges. Try: sudo $0"
fi

read -p "Enter Salt Master IP [Default: $DEFAULT_MASTER_IP]: " INPUT_IP
SALT_MASTER_IP=${INPUT_IP:-$DEFAULT_MASTER_IP}
log "Using Master IP: $SALT_MASTER_IP"

read -p "Enter a unique Minion ID (Press ENTER to use system hostname): " MINION_ID
if [ -z "$MINION_ID" ]; then
    MINION_ID=$(hostname -f)
fi
log "Using Minion ID: $MINION_ID"

log "Cleaning up any existing service states..."
systemctl stop salt-minion 2>/dev/null || true

log "Detecting OS and configuring repositories for Salt 3007..."

if command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    
    # Ubuntu 24.04+ blocks SHA-1 by default via OpenSSL config.
    # We lower SECLEVEL from 2 to 1 to allow SHA-1 (matching RHEL's DEFAULT:SHA1 policy).
    if grep -q "SECLEVEL=2" /etc/ssl/openssl.cnf; then
        log "Lowering OpenSSL Security Level to allow SHA-1..."
        sed -i 's/SECLEVEL=2/SECLEVEL=1/g' /etc/ssl/openssl.cnf
    fi
    # --------------------------------
    
    $PKG_MGR update -y > /dev/null
    $PKG_MGR install -y curl gnupg2 > /dev/null

    mkdir -p /etc/apt/keyrings
    # Remove old key if exists to ensure we have the latest
    rm -f /etc/apt/keyrings/salt-archive-keyring.pgp
    curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null
    
    ARCH=$(dpkg --print-architecture)
    
    log "Detected System: Debian/Ubuntu [$ARCH]"

    echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.pgp arch=$ARCH] https://packages.broadcom.com/artifactory/saltproject-deb/ stable main" | tee /etc/apt/sources.list.d/salt.list > /dev/null
    
    # Pin Priority (Force version 3007 to avoid unexpected upgrades)
    cat <<EOF > /etc/apt/preferences.d/salt-pin-1001
Package: salt-*
Pin: version 3007.*
Pin-Priority: 1001
EOF
    $PKG_MGR update -y
    INSTALL_CMD="$PKG_MGR install -y salt-minion"


elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
    
    if command -v update-crypto-policies &> /dev/null; then
        log "Enabling SHA-1 Crypto Policy for Salt compatibility..."
        update-crypto-policies --set DEFAULT:SHA1
    fi
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        # For Fedora, we treat it like RHEL 9 for the repo URL usually, or detect specific version
        if [[ "$ID" == "fedora" ]]; then
             EL_VERSION="9" 
        else
             EL_VERSION=$(echo $VERSION_ID | cut -d. -f1)
        fi
    else
        EL_VERSION=$(rpm -E %rhel)
    fi
    
    log "Detected System: RHEL/Fedora/EL Version $EL_VERSION"


    REPO_RPM_URL="https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${EL_VERSION}/x86_64/3007/salt-repo-3007-${EL_VERSION}.noarch.rpm"
    
    log "Installing Repo RPM..."
    $PKG_MGR install -y "$REPO_RPM_URL" || log "Repo RPM might already be installed."

    $PKG_MGR clean expire-cache
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

else
    error "Unsupported OS. Only apt (Debian/Ubuntu) and dnf/yum (RHEL/Fedora) are supported."
fi

log "Installing Salt Minion package..."
eval $INSTALL_CMD || error "Failed to install salt-minion."

# Ubuntu Fix. Yay. 
log "Stopping service for configuration..."
systemctl stop salt-minion
systemctl disable salt-minion 2>/dev/null || true

log "Configuring /etc/salt/minion.d/master.conf..."
mkdir -p /etc/salt/minion.d
# Revert to standard config (no hash_type enforcement) since we are allowing SHA1 at OS level
echo "master: $SALT_MASTER_IP" > /etc/salt/minion.d/master.conf

log "Setting Minion ID to $MINION_ID..."
echo "$MINION_ID" > /etc/salt/minion_id

log "Enabling and Starting Salt Minion..."
systemctl enable salt-minion
systemctl start salt-minion

log "Waiting for initialization (5s)..."
sleep 5

# Ubuntu/Debian often fail DNS resolution or binding on the very first start.
# This forced restart clears that state and ensures a clean connection.
log "Performing stability restart..."
systemctl restart salt-minion

if systemctl is-active --quiet salt-minion; then
    log "Service is ACTIVE."
else
    warn "Service NOT active. Retrying one last time..."
    sleep 5
    systemctl restart salt-minion
    if systemctl is-active --quiet salt-minion; then
        log "Service is ACTIVE after retry."
    else
        warn "Service failed to start. Run 'systemctl status salt-minion' to debug."
    fi
fi

if [ -d "../Tools" ]; then
    log "Copying tools to /etc/runtl..."
    mkdir -p /etc/runtl
    cp -r ../Tools/* /etc/runtl/
else
    log "Tools directory not found, skipping copy." 
fi

echo ""
echo "#####################################################"
echo "# MINION SETUP COMPLETE" 
echo "#####################################################"
echo "Minion ID: $MINION_ID"
echo "Master IP: $SALT_MASTER_IP"
echo "Crypto:    SHA-1 Permitted"
echo "Status:    $(systemctl is-active salt-minion)"
echo "#####################################################"