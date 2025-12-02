#!/bin/bash

# ==============================================================================
# Salt Minion Universal Installer (Bootstrap Method)
# Supported: Ubuntu 20.04/22.04+, CentOS 7, RHEL 8/9, Debian 10+
# Version: Pins to Salt 3006 LTS (Max Compatibility for CentOS 7)
# ==============================================================================

SCRIPT_TITLE="Salt Minion Universal Installer"
DEFAULT_MASTER_IP="172.20.242.20"
# We pin to 3006 because it is the reliable LTS for CentOS 7
SALT_VERSION="3006" 

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

# Ensure curl is installed (needed for bootstrap)
if ! command -v curl &> /dev/null; then
    log "Installing curl..."
    if command -v apt-get &> /dev/null; then apt-get update && apt-get install -y curl
    elif command -v yum &> /dev/null; then yum install -y curl
    fi
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

# --- 3. Clean Previous Installs ---
log "Cleaning up any existing service states..."
systemctl stop salt-minion 2>/dev/null || true
# We do NOT remove packages, as the bootstrap handles upgrades/reinstalls gracefully.

# --- 4. Installation (Via Official Bootstrap) ---
log "Downloading Salt Bootstrap..."
curl -o bootstrap-salt.sh -L https://raw.githubusercontent.com/saltstack/salt-bootstrap/refs/heads/develop/bootstrap-salt.sh

log "Running Bootstrap (Installing Salt $SALT_VERSION)..."
# Flags:
# -P: Allow pip installation if needed (fallback)
# -x python3: Force Python 3
# stable $SALT_VERSION: Install specific stable version
sh bootstrap-salt.sh -P -x python3 stable $SALT_VERSION

if [ $? -ne 0 ]; then
    error "Bootstrap installation failed. Check network or logs above."
fi

# --- 5. Configuration & Ubuntu Fix ---

log "Stopping service for configuration..."
# CRITICAL: Stop service immediately. Ubuntu starts it unconfigured, which causes
# the process to hang or fail if we try to restart it too quickly.
systemctl stop salt-minion
sleep 2

log "Configuring /etc/salt/minion.d/master.conf..."
mkdir -p /etc/salt/minion.d
echo "master: $SALT_MASTER_IP" > /etc/salt/minion.d/master.conf

log "Setting Minion ID to $MINION_ID..."
echo "$MINION_ID" > /etc/salt/minion_id

# --- 6. Service Start (The "Double Restart" Fix) ---
log "Starting Salt Minion..."
systemctl enable salt-minion
systemctl start salt-minion

log "Waiting for initialization (5s)..."
sleep 5

# Ubuntu/Debian often fail DNS resolution or binding on the very first start 
# after install. This forced restart clears that state.
log "Performing stability restart (Ubuntu/Debian fix)..."
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
    fi
fi

# --- 7. Post-Install Tasks ---
if [ -d "../Tools" ]; then
    log "Copying tools to /etc/runtl..."
    mkdir -p /etc/runtl
    cp -r ../Tools/* /etc/runtl/
else
    warn "../Tools directory not found. Skipping tool copy."
fi

# Cleanup bootstrap file
rm -f bootstrap-salt.sh

echo ""
echo "#####################################################"
echo "# MINION SETUP COMPLETE" 
echo "#####################################################"
echo "Minion ID: $MINION_ID"
echo "Master IP: $SALT_MASTER_IP"
echo "Version:   Salt $SALT_VERSION (LTS)"
echo "Status:    $(systemctl is-active salt-minion)"
echo "#####################################################"