#!/bin/bash

# ==============================================================================
# Automated Salt-GUI Deployment Script (Bootstrap Edition)
# ==============================================================================
#
# Installs and configures the Salt master and API using the official Bootstrap
# script to ensure perfect repo setup and version matching (3007).
#
# Samuel Brucker 2025-2026
#

set -e

SOURCE_DIR="../SaltyBoxes/Salt-GUI"
INSTALL_DIR="/opt/salt-gui"
# Defaults
SALT_USER="saltgui"
SALT_PASS="PlzNoHackThisAccountItsUseless!"
API_PORT=8881
GUI_PORT=3000

# Salt Master Config File Location
MASTER_CONF="/etc/salt/master"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root."
   exit 1
fi

# Service Cleanup (Clean slate)
log "Cleaning up existing services..."
systemctl stop salt-gui salt-minion salt-master salt-api 2>/dev/null || true

SERVER_IP=$(hostname -I | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="localhost" && warn "Could not detect IP. Defaulting to localhost."
log "Detected Server IP: $SERVER_IP"

# ------------------------------------------------------------------
# STEP 1: Run Salt Bootstrap (Installs Repo + Master + Minion)
# ------------------------------------------------------------------
# ------------------------------------------------------------------
log "Preparing to install Salt Master & Minion (Version 3007)..."

BOOTSTRAP_URL="https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh"


if curl -L -o bootstrap-salt.sh --connect-timeout 10 --max-time 35 "$BOOTSTRAP_URL"; then
    log "Download successful via Curl."
    log "Running Bootstrap to install Salt Master, API, and Minion (Version 3007)..."
    # -M: Install Master
    # -W: Install API
    # -P: Allow Pip-based installation if needed
    # -x python3: Force Python 3
    # stable 3007: Pin to the 3007.x branch
    sh bootstrap-salt.sh -M -W -P -x python3 stable 3007
else
    warn "Curl download failed (Firewall blocked?). Falling back to Git Clone method..."

    log "Installing Git for fallback..."
    if command -v dnf &> /dev/null; then
        dnf install -y git
    elif command -v yum &> /dev/null; then
        yum install -y git
    elif command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y git
    fi

    log "Cloning Salt Bootstrap Repository..."
    rm -rf salt-bootstrap # Cleanup previous attempts
    git clone https://github.com/saltstack/salt-bootstrap.git
    
    cd salt-bootstrap
    log "Running Bootstrap from Git Source..."
    sh bootstrap-salt.sh -M -W -P -x python3 stable 3007
    cd ..
    rm -rf salt-bootstrap
fi
# ------------------------------------------------------------------
# STEP 2: Install Salt API & Dependencies (Post-Bootstrap)
# ------------------------------------------------------------------
log "Installing Salt API and GUI dependencies..."

if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
    
    $PKG_MGR install -y policycoreutils-python-utils
    
    # Install Node.js for the GUI
    $PKG_MGR module enable -y nodejs:18 || $PKG_MGR module enable -y nodejs:16 || true
    $PKG_MGR install -y nodejs npm python3-pip

elif command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    $PKG_MGR install -y nodejs build-essential
    $PKG_MGR install -y python3-cherrypy3 || pip3 install cherrypy
else
    error "No supported package manager found."
    exit 1
fi

# ------------------------------------------------------------------
# STEP 3: Configure User & Salt Master
# ------------------------------------------------------------------
log "Configuring system user '$SALT_USER'..."
if ! id "$SALT_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$SALT_USER"
fi
echo "$SALT_USER:$SALT_PASS" | chpasswd

log "Configuring Salt Master and API (Monolithic Config)..."

# Ensure /etc/salt/master exists
if [ ! -f "$MASTER_CONF" ]; then
    touch "$MASTER_CONF"
fi

# Force User to Root
sed -i '/^user:/d' "$MASTER_CONF"
echo "user: root" >> "$MASTER_CONF"

sed -i '/# --- SALT GUI AUTOMATED CONFIG START ---/,/# --- SALT GUI AUTOMATED CONFIG END ---/d' "$MASTER_CONF"

cat <<EOF >> "$MASTER_CONF"
# --- SALT GUI AUTOMATED CONFIG START ---

netapi_enable_clients:
  - local
  - runner
  - wheel

rest_cherrypy:
  port: $API_PORT
  host: 0.0.0.0
  disable_ssl: True

external_auth:
  pam:
    $SALT_USER:
      - .*
      - '@wheel'
      - '@runner'
      - '@jobs'

# --- SALT GUI AUTOMATED CONFIG END ---
EOF

log "Configuring Local Salt Minion..."
echo "master: localhost" > /etc/salt/minion.d/master.conf
echo "salt-master-gui" > /etc/salt/minion_id

# ------------------------------------------------------------------
# STEP 4: Deploy GUI & Start Services
# ------------------------------------------------------------------
log "Deploying Salt-GUI from $SOURCE_DIR to $INSTALL_DIR..."

rm -rf "$INSTALL_DIR"
cp -r "$SOURCE_DIR" "$INSTALL_DIR"

CONFIG_FILE="$INSTALL_DIR/config.json"
log "Updating config.json with Server IP ($SERVER_IP)..."

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
except Exception as e:
    print(f'Error updating config: {e}')
    sys.exit(1)
"

chown -R "$SALT_USER:$SALT_USER" "$INSTALL_DIR"

log "Setting up Custom Scripts..."
mkdir -p /srv/salt
if [ -d "../SaltyBoxes/CustomScripts/" ]; then
    cp -r ../SaltyBoxes/CustomScripts/* /srv/salt/
else
    warn "CustomScripts folder not found in parent directory. Skipping copy."
fi

log "Installing Node.js dependencies..."
cd "$INSTALL_DIR"
npm install --unsafe-perm

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

log "Starting Services..."
systemctl daemon-reload
systemctl enable --now salt-master
systemctl enable --now salt-minion
systemctl enable --now salt-api
systemctl enable --now salt-gui

# Restart minion to ensure it connects to the now-running master
systemctl restart salt-minion

log "Waiting for local minion to contact master..."
sleep 5

log "Accepting local minion key..."
salt-key -y -a "salt-master-gui" || warn "Key 'salt-master-gui' not found yet. You may need to accept it in the GUI."

log "Deployment Complete!"
echo "--------------------------------------------------------"
echo "Salt-GUI Accessible at: http://$SERVER_IP:$GUI_PORT"
echo "Salt-API Accessible at: http://$SERVER_IP:$API_PORT"
echo "User: $SALT_USER"
echo "--------------------------------------------------------"