#!/bin/bash

# ==============================================================================
# Salt Minion Manual Installer (No Bootstrap)
# Targets: Salt 3007 LTS (Unified Version)
# Supported: Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma/Oracle 8+
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

# --- 4. OS Detection & Repo Setup (Manual Method) ---
log "Detecting OS and configuring repositories for Salt 3007..."

if command -v apt-get &> /dev/null; then
    # ==========================================
    # Debian / Ubuntu Logic
    # ==========================================
    PKG_MGR="apt-get"
    
    # 1. Install Dependencies
    $PKG_MGR update -y > /dev/null
    $PKG_MGR install -y curl gnupg2 > /dev/null

    # 2. Setup Keyrings (Broadcom Key)
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null
    
    # 3. Detect Architecture and Codename
    ARCH=$(dpkg --print-architecture)
    # Robust codename detection
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        CODENAME=$VERSION_CODENAME
    fi
    if [ -z "$CODENAME" ]; then
        CODENAME=$(lsb_release -cs)
    fi
    
    log "Detected System: Debian/Ubuntu ($CODENAME) [$ARCH]"

    # 4. Write Sources List (Pointing to Salt 3007)
    echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.pgp arch=$ARCH] https://packages.broadcom.com/artifactory/saltproject-deb/ stable/3007 $CODENAME main" | tee /etc/apt/sources.list.d/salt.list > /dev/null
    
    # 5. Pin Priority (Ensure we don't pick up old OS packages)
    cat <<EOF > /etc/apt/preferences.d/salt-pin-1001
Package: salt-*
Pin: origin packages.broadcom.com
Pin-Priority: 1001
EOF

    # 6. Install
    $PKG_MGR update -y
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    # ==========================================
    # RHEL / CentOS / Rocky / Alma Logic
    # ==========================================
    if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
    
    # 1. Detect RHEL Version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        EL_VERSION=$(echo $VERSION_ID | cut -d. -f1)
    else
        EL_VERSION=$(rpm -E %rhel)
    fi
    
    log "Detected System: RHEL/EL Version $EL_VERSION"

    # 2. Install Salt Repo RPM
    # We install the repo RPM directly from Broadcom to configure the .repo file automatically
    REPO_RPM_URL="https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${EL_VERSION}/x86_64/3007/salt-repo-3007-${EL_VERSION}.noarch.rpm"
    
    log "Installing Repo RPM..."
    $PKG_MGR install -y "$REPO_RPM_URL" || log "Repo RPM might already be installed."

    # 3. Clean and Install
    $PKG_MGR clean expire-cache
    INSTALL_CMD="$PKG_MGR install -y salt-minion"

else
    error "Unsupported OS. Only apt (Debian/Ubuntu) and dnf/yum (RHEL/CentOS) are supported."
fi

# --- 5. Installation ---
log "Installing Salt Minion package..."
eval $INSTALL_CMD || error "Failed to install salt-minion."

# --- 6. Service Handling (The Ubuntu Fix) ---
log "Stopping service for configuration..."
# STOP immediately. This prevents the "start failure" loop on Ubuntu/Debian
# that happens when the package starts unconfigured.
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

# Ubuntu/Debian often fail DNS resolution or binding on the very first start 
# after install. This forced restart clears that state.
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