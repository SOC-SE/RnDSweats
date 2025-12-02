#!/bin/bash

# ==============================================================================
# Automated Salt-GUI Deployment Script (Updated)
# ==============================================================================

set -e

# --- Configuration ---
SOURCE_DIR="./Salt-GUI"
INSTALL_DIR="/opt/salt-gui"
SALT_USER="saltgui"
SALT_PASS="PlzNoHackThisAccountItsUseless!"
API_PORT=8881
GUI_PORT=3000

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }

# --- 1. Pre-flight Checks ---
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root."
   exit 1
fi

git clone https://github.com/KySchwartz/Salt-GUI --branch=master

if [ ! -d "$SOURCE_DIR" ]; then
    error "Directory '$SOURCE_DIR' not found in current location."
    echo "Please run this script from the directory containing the Salt-GUI folder."
    exit 1
fi

# Detect Server IP (for config.json)
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="localhost"
    warn "Could not detect IP address. Defaulting to localhost."
else
    log "Detected Server IP: $SERVER_IP"
fi

# --- 2. Install Dependencies (OS Agnostic) ---
log "Detecting package manager and installing dependencies..."

if command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
    $PKG_MGR install -y epel-release || true
    $PKG_MGR install -y https://repo.saltproject.io/salt/py3/redhat/salt-repo-latest.el9.noarch.rpm || true
    $PKG_MGR makecache
    # Try installing Node 18, fall back if needed
    $PKG_MGR module enable -y nodejs:18 || $PKG_MGR module enable -y nodejs:16 || true
    $PKG_MGR install -y nodejs npm python3-pip salt-master salt-minion salt-api salt-ssh

elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
    $PKG_MGR install -y epel-release || true
    $PKG_MGR install -y https://repo.saltproject.io/salt/py3/redhat/salt-repo-latest.el9.noarch.rpm || true
    $PKG_MGR makecache
    curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
    $PKG_MGR install -y nodejs npm python3-pip salt-master salt-minion salt-api salt-ssh

elif command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    $PKG_MGR update
    $PKG_MGR install -y curl gnupg2
    
    # Bootstrap Salt (safer for varied Debian/Ubuntu/Mint versions)
    curl -fsSL https://bootstrap.saltproject.io -o install_salt.sh
    sh install_salt.sh -M -P -x python3
    
    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    $PKG_MGR install -y nodejs build-essential salt-api
    
    # Ensure cherrypy
    $PKG_MGR install -y python3-cherrypy3 || pip3 install cherrypy
else
    error "No supported package manager found (dnf, yum, apt)."
    exit 1
fi

# --- 3. Configure System User ---
log "Configuring system user '$SALT_USER'..."
if id "$SALT_USER" &>/dev/null; then
    echo "$SALT_USER:$SALT_PASS" | chpasswd
else
    useradd -m -s /bin/bash "$SALT_USER"
    echo "$SALT_USER:$SALT_PASS" | chpasswd
fi

# --- 4. Configure Salt Master & API ---
log "Configuring Salt Master and API..."

MASTER_CONF_DIR="/etc/salt/master.d"
mkdir -p "$MASTER_CONF_DIR"

# External Auth (PAM)
cat <<EOF > "$MASTER_CONF_DIR/auth.conf"
external_auth:
  pam:
    $SALT_USER:
      - .*
      - '@wheel'
      - '@runner'
      - '@jobs'
EOF

# API Config (CherryPy) - SSL Disabled, Exposed to 0.0.0.0
cat <<EOF > "$MASTER_CONF_DIR/api.conf"
rest_cherrypy:
  port: $API_PORT
  host: 0.0.0.0
  disable_ssl: True
EOF

# --- 5. Configure Salt Minion (Local) ---
log "Configuring Local Salt Minion..."
echo "master: localhost" > /etc/salt/minion.d/master.conf
echo "id: salt-master-gui" > /etc/salt/minion_id

# --- 6. Deploy GUI Application ---
log "Deploying Salt-GUI from $SOURCE_DIR to $INSTALL_DIR..."

# Clean old install if exists
rm -rf "$INSTALL_DIR"
# Copy directory
cp -r "$SOURCE_DIR" "$INSTALL_DIR"

# Configure config.json
# We use jq if available, otherwise python one-liner to edit JSON safely, or simple sed replacement
CONFIG_FILE="$INSTALL_DIR/config.json"

log "Updating config.json with Server IP ($SERVER_IP)..."
# Using python for reliable JSON manipulation without requiring jq installation
python3 -c "
import json
import sys

config_path = '$CONFIG_FILE'
try:
    with open(config_path, 'r') as f:
        data = json.load(f)
    
    # Update values
    data['proxyURL'] = ''
    data['saltAPIUrl'] = 'http://0.0.0.0:$API_PORT'
    data['username'] = '$SALT_USER'
    data['password'] = '$SALT_PASS'
    data['eauth'] = 'pam'
    
    with open(config_path, 'w') as f:
        json.dump(data, f, indent=2)
    print('Config updated successfully.')
except Exception as e:
    print(f'Error updating config: {e}')
    sys.exit(1)
"

# Set Permissions
chown -R "$SALT_USER:$SALT_USER" "$INSTALL_DIR"

# Install Node Modules
log "Installing Node.js dependencies..."
cd "$INSTALL_DIR"
# Run as user to avoid root-owned node_modules issues, or run as root with --unsafe-perm
npm install --unsafe-perm

# --- 7. Create Systemd Service ---
log "Creating Salt-GUI Systemd Service..."
cat <<EOF > /etc/systemd/system/salt-gui.service
[Unit]
Description=Salt GUI Web Server
After=network.target salt-api.service

[Service]
Type=simple
User=$SALT_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# --- 8. Start Services ---
log "Starting Services..."
systemctl daemon-reload
systemctl enable --now salt-master
systemctl enable --now salt-minion
systemctl enable --now salt-api
systemctl enable --now salt-gui

# Restart minion to pick up new master config
systemctl restart salt-minion

log "Deployment Complete!"
echo "--------------------------------------------------------"
echo "Salt-GUI Accessible at: http://$SERVER_IP:$GUI_PORT"
echo "Salt-API Accessible at: http://$SERVER_IP:$API_PORT"
echo "User: $SALT_USER"
echo "--------------------------------------------------------"