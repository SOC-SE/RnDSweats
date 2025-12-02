#!/bin/bash

# ==============================================================================
# Automated Salt-GUI Deployment Script (Final Competition Version)
# ==============================================================================
#
# Installs and configures the Salt master and API, as well as the custom SaltGUI
# 
# Samuel Brucker 2025-2026
#
# Just about 100% of the credit for the development of the SaltGUI goes to Kyle Schwartz
# Their LinkedIn; go say hi and compliment them if you use this tool: https://www.linkedin.com/in/kyle-schwartz-643542271/
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

# Service Cleanup
log "Cleaning up existing services..."
systemctl stop salt-gui salt-minion salt-master salt-api 2>/dev/null || true

SERVER_IP=$(hostname -I | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="localhost" && warn "Could not detect IP. Defaulting to localhost."
log "Detected Server IP: $SERVER_IP"

log "Detecting package manager and installing dependencies..."

if command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
    $PKG_MGR install -y epel-release || true
    $PKG_MGR install -y https://repo.saltproject.io/salt/py3/redhat/salt-repo-latest.el9.noarch.rpm || true
    $PKG_MGR makecache
    $PKG_MGR module enable -y nodejs:18 || $PKG_MGR module enable -y nodejs:16 || true
    $PKG_MGR install -y nodejs npm python3-pip salt-master salt-minion salt-api salt-ssh policycoreutils-python-utils

elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
    $PKG_MGR install -y epel-release || true
    $PKG_MGR install -y https://repo.saltproject.io/salt/py3/redhat/salt-repo-latest.el9.noarch.rpm || true
    $PKG_MGR makecache
    curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
    $PKG_MGR install -y nodejs npm python3-pip salt-master salt-minion salt-api salt-ssh policycoreutils-python-utils

elif command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    $PKG_MGR update
    $PKG_MGR install -y curl gnupg2
    curl -fsSL https://bootstrap.saltproject.io -o install_salt.sh
    sh install_salt.sh -M -P -x python3
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    $PKG_MGR install -y nodejs build-essential salt-api
    $PKG_MGR install -y python3-cherrypy3 || pip3 install cherrypy
else
    error "No supported package manager found."
    exit 1
fi

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

configure_selinux() {
    if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        log "Checking SELinux configuration..."
        
        # Check if SELinux is enforcing
        if sestatus | grep "Current mode:" | grep -q "enforcing"; then
            log "SELinux is enforcing. Applying rules..."
            
            # Allow GUI Port (default 3000)
            if ! semanage port -l | grep http_port_t | grep -qw "$GUI_PORT"; then
                log "Adding SELinux rule for port $GUI_PORT..."
                semanage port -a -t http_port_t -p tcp "$GUI_PORT" || warn "Failed to add port $GUI_PORT context."
            else
                log "Port $GUI_PORT already allowed."
            fi

            # Allow Node.js/HTTPD scripts to connect to network (aka, let the server actually work)
            setsebool -P daemons_enable_cluster_mode 1 || warn "Could not set daemons_enable_cluster_mode."
            setsebool -P httpd_can_network_connect 1 || true 
        else
            log "SELinux is not enforcing. Skipping configuration."
        fi
    fi
}

configure_selinux

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