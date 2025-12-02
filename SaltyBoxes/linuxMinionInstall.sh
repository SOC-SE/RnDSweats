#!/bin/bash

# ==============================================================================
# Salt Minion Manual Installer (Broadcom/Onedir)
# Targets: Salt 3007 LTS
# Supported: Ubuntu 20.04/22.04/24.04, Debian 11+, RHEL/Fedora/Rocky 8/9
# ==============================================================================

SCRIPT_TITLE="Salt Minion Manual Installer"
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
    error "This script must be run with root privileges. Try: sudo $0"
fi

# --- 2. User Input ---
# Default IP is set to 172.20.242.20. User can just hit Enter.
read -p "Enter Salt Master IP [Default: $DEFAULT_MASTER_IP]: " INPUT_IP
SALT_MASTER_IP=${INPUT_IP:-$DEFAULT_MASTER_IP}
log "Using Master IP: $SALT_MASTER_IP"

read -p "Enter a unique Minion ID (Press ENTER to use system hostname): " MINION_ID
if [ -z "$MINION_ID" ]; then
    MINION_ID=$(hostname -f)
fi
log "Using Minion ID: $MINION_ID"

# --- 3. Clean Previous Installs ---
log "Cleaning up any existing service states..."
systemctl stop salt-minion 2>/dev/null || true

# --- 4. OS Detection & Repo Setup ---
log "Detecting OS and configuring repositories for Salt 3007..."

if command -v apt-get &> /dev/null; then
    # ==========================================
    # Debian / Ubuntu Logic (Broadcom Onedir)
    # ==========================================
    PKG_MGR="apt-get"
    
    # 1. Install Dependencies
    $PKG_MGR update -y > /dev/null
    $PKG_MGR install -y curl gnupg2 > /dev/null

    # 2. Setup Keyrings
    mkdir -p /etc/apt/keyrings
    # Remove old key if exists to ensure we have the latest
    rm -f /etc/apt/keyrings/salt-archive-keyring.pgp
    curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null
    
    # 3. Detect Architecture
    ARCH=$(dpkg --print-architecture)
    
    log "Detected System: Debian/Ubuntu [$ARCH]"

    # 4. Write Sources List (Corrected for Broadcom)
    # Note: We do NOT use the codename (e.g. jammy) in the path anymore. 
    # The suite is simply 'stable' for the Broadcom Onedir repo.
    echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.pgp arch=$ARCH] https://packages.broadcom.com/artifactory/saltproject-deb/ stable main" | tee /etc/apt/sources.list.d/salt.list > /dev/null
    
    # 5. Pin Priority (Force version 3007 to avoid unexpected upgrades)
    cat <<EOF > /etc/apt/preferences.d/salt-pin-1001
Package: salt-*
Pin: version 3007.*
Pin-Priority: 1001
EOF

    # 6. Install
    $PKG_MGR update -y
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    # ==========================================
    # RHEL / Fedora / Rocky / Alma Logic
    # ==========================================
    if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
    
    # 1. Detect RHEL Version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        # For Fedora, we treat it like RHEL 9 for the repo URL usually, or detect specific version
        if [[ "$ID" == "fedora" ]]; then
             EL_VERSION="9" # Fedora works well with EL9 packages usually
        else
             EL_VERSION=$(echo $VERSION_ID | cut -d. -f1)
        fi
    else
        EL_VERSION=$(rpm -E %rhel)
    fi
    
    log "Detected System: RHEL/Fedora/EL Version $EL_VERSION"

    # 2. Install Salt Repo RPM
    # This automatically configures the .repo file for 3007
    REPO_RPM_URL="https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${EL_VERSION}/x86_64/3007/salt-repo-3007-${EL_VERSION}.noarch.rpm"
    
    log "Installing Repo RPM..."
    $PKG_MGR install -y "$REPO_RPM_URL" || log "Repo RPM might already be installed."

    # 3. Clean and Install
    $PKG_MGR clean expire-cache
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

else
    error "Unsupported OS. Only apt (Debian/Ubuntu) and dnf/yum (RHEL/Fedora) are supported."
fi

# --- 5. Installation ---
log "Installing Salt Minion package..."
eval $INSTALL_CMD || error "Failed to install salt-minion."

# --- 6. Service Handling (The Ubuntu Fix) ---
log "Stopping service for configuration..."
# STOP immediately. Ubuntu/Debian packages often auto-start the service 
# in a broken state before config is applied.
systemctl stop salt-minion
systemctl disable salt-minion 2>/dev/null || true

# --- 7. Configuration ---
log "Configuring /etc/salt/minion.d/master.conf..."
mkdir -p /etc/salt/minion.d
echo "master: $SALT_MASTER_IP" > /etc/salt/minion.d/master.conf

log "Setting Minion ID to $MINION_ID..."
echo "$MINION_ID" > /etc/salt/minion_id

# --- 8. Service Start (The "Double Restart" Fix) ---
log "Enabling and Starting Salt Minion..."
systemctl enable salt-minion
systemctl start salt-minion

log "Waiting for initialization (5s)..."
sleep 5

# Ubuntu/Debian often fail DNS resolution or binding on the very first start.
# This forced restart clears that state and ensures a clean connection.
log "Performing stability restart..."
systemctl restart salt-minion

# Verify Status
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
        # Don't exit, assume user might fix config later
    fi
fi

# --- 9. Post-Install Tasks ---
if [ -d "../Tools" ]; then
    log "Copying tools to /etc/runtl..."
    mkdir -p /etc/runtl
    cp -r ../Tools/* /etc/runtl/
else
    # Only warn if directory missing, don't error
    log "Tools directory not found, skipping copy." 
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