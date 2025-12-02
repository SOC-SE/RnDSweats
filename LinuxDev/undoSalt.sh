#!/bin/bash

# ==============================================================================
# Automated Salt-GUI Uninstall Script
# Reverses the installation of Salt-GUI and its dependencies.
# ==============================================================================

set -e

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root."
   exit 1
fi

log "Starting uninstallation..."

# --- 1. Stop and Disable Services ---
log "Stopping and disabling services..."
SERVICES=("salt-gui" "salt-api" "salt-master" "salt-minion")

for SERVICE in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$SERVICE"; then
        echo "Stopping $SERVICE..."
        systemctl stop "$SERVICE"
    fi
    if systemctl is-enabled --quiet "$SERVICE"; then
        echo "Disabling $SERVICE..."
        systemctl disable "$SERVICE"
    fi
done

# --- 2. Remove Systemd Service ---
if [ -f /etc/systemd/system/salt-gui.service ]; then
    log "Removing salt-gui systemd service..."
    rm -f /etc/systemd/system/salt-gui.service
    systemctl daemon-reload
fi

# --- 3. Remove Application Files ---
if [ -d /opt/salt-gui ]; then
    log "Removing Salt-GUI directory (/opt/salt-gui)..."
    rm -rf /opt/salt-gui
fi

# --- 4. Remove Salt Configurations ---
log "Removing Salt configuration files created by the script..."
rm -f /etc/salt/master.d/auth.conf
rm -f /etc/salt/master.d/api.conf
rm -f /etc/salt/minion.d/master.conf
rm -f /etc/salt/minion_id

# --- 5. Remove System User ---
if id "sysadmin" &>/dev/null; then
    log "Removing user 'sysadmin'..."
    userdel -r sysadmin || warn "Could not fully remove user sysadmin (might be logged in or running processes)."
fi

# --- 6. Uninstall Packages ---
log "Uninstalling packages..."

if command -v dnf &> /dev/null; then
    # RHEL / Oracle Linux / Fedora
    PKG_MGR="dnf"
    $PKG_MGR remove -y salt-master salt-minion salt-api salt-ssh 
    $PKG_MGR remove -y nodejs npm jq
    # Optional: Remove pip if we installed it, though it's common system-wide
    # $PKG_MGR remove -y python3-pip 
    $PKG_MGR autoremove -y

elif command -v yum &> /dev/null; then
    # Older RHEL / CentOS
    PKG_MGR="yum"
    $PKG_MGR remove -y salt-master salt-minion salt-api salt-ssh
    $PKG_MGR remove -y nodejs npm jq
    $PKG_MGR autoremove -y

elif command -v apt-get &> /dev/null; then
    # Debian / Ubuntu
    PKG_MGR="apt-get"
    $PKG_MGR remove -y --purge salt-master salt-minion salt-api salt-ssh
    $PKG_MGR remove -y --purge nodejs npm python3-cherrypy3 jq
    $PKG_MGR autoremove -y
else
    warn "Could not detect package manager to uninstall packages automatically."
fi

# --- 7. Clean up Pip Packages (if applicable) ---
if command -v pip3 &> /dev/null; then
    if pip3 show cherrypy &> /dev/null; then
        log "Uninstalling CherryPy via pip..."
        pip3 uninstall -y cherrypy
    fi
fi

log "Uninstallation Complete."
echo "--------------------------------------------------------"
echo "The system should be clean of Salt-GUI and SaltStack components."
echo "Note: If you had Node.js or Salt installed prior to the install script,"
echo "they have been removed. Re-install them manually if needed."
echo "--------------------------------------------------------"