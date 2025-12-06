#!/bin/bash

# ==============================================================================
# Automated Salt-GUI Deployment Script (Ubuntu Onedir Fix)
# ==============================================================================
#
# - Installs Salt 3007 (Master + API + Minion)
# - Fixes Ubuntu 24.04 Auth by installing 'python-pam' into Salt's Onedir Python
# - Universal SHA-1/SSL Compatibility
#
# Samuel Brucker 2025-2026
#

set -e

SOURCE_DIR="../SaltyBoxes/Salt-GUI"
INSTALL_DIR="/opt/salt-gui"
SALT_USER="hiblueteam"
# Changed password to alphanumeric to prevent shell expansion issues with '!'
SALT_PASS="BlueTeamSaltAdmin2025"
API_PORT=8881
GUI_PORT=3000
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

log "Cleaning up existing services..."
systemctl stop salt-gui salt-minion salt-master salt-api 2>/dev/null || true

SERVER_IP=$(hostname -I | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="localhost" && warn "Could not detect IP. Defaulting to localhost."
log "Detected Server IP: $SERVER_IP"

log "Detecting package manager and installing dependencies..."

if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
    
    # RHEL/Oracle Crypto Fix (SHA-1)
    if command -v update-crypto-policies &> /dev/null; then
        log "Enabling SHA-1 Crypto Policy for Salt compatibility..."
        update-crypto-policies --set DEFAULT:SHA1
    fi

    # OS Detection
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "fedora" ]]; then
             EL_VERSION="9" 
        else
             EL_VERSION=$(echo $VERSION_ID | cut -d. -f1)
        fi
    else
        EL_VERSION=$(rpm -E %rhel)
    fi
    log "Detected Enterprise Linux Version: $EL_VERSION"

    $PKG_MGR install -y epel-release || true
    
    log "Removing old/conflicting Salt repositories..."
    rpm -e --nodeps salt-repo 2>/dev/null || true
    rm -f /etc/yum.repos.d/salt.repo
    $PKG_MGR clean all

    log "Configuring Salt 3007 Repository (Manual Write)..."
    cat <<EOF > /etc/yum.repos.d/salt.repo
[salt-repo-3007-sts]
name=Salt Repo for Salt v3007 STS
baseurl=https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${EL_VERSION}/x86_64/3007
skip_if_unavailable=True
priority=10
enabled=1
enabled_metadata=1
gpgcheck=1
exclude=*3006* *3008* *3009* *3010*
gpgkey=https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public
EOF
    
    $PKG_MGR makecache
    $PKG_MGR module enable -y nodejs:18 || $PKG_MGR module enable -y nodejs:16 || true
    
    log "Upgrading/Installing Salt Components..."
    $PKG_MGR install -y nodejs npm python3-pip salt-master salt-api salt-minion policycoreutils-python-utils

elif command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    
    # Debian/Ubuntu Crypto Fix (SHA-1)
    if [ -f /etc/ssl/openssl.cnf ]; then
        if grep -q "SECLEVEL=2" /etc/ssl/openssl.cnf; then
            log "Lowering OpenSSL Security Level to allow SHA-1..."
            sed -i 's/SECLEVEL=2/SECLEVEL=1/g' /etc/ssl/openssl.cnf
        else
            log "OpenSSL Security Level allows SHA-1 (or SECLEVEL not set to 2). Skipping."
        fi
    fi

    log "Configuring Salt 3007 Repository (Debian/Ubuntu)..."
    $PKG_MGR update
    $PKG_MGR install -y curl gnupg2

    mkdir -p /etc/apt/keyrings
    rm -f /etc/apt/keyrings/salt-archive-keyring.pgp
    
    # Fetch Broadcom/Salt Key
    curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null
    
    ARCH=$(dpkg --print-architecture)
    
    # Add Repo
    echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.pgp arch=$ARCH] https://packages.broadcom.com/artifactory/saltproject-deb/ stable main" | tee /etc/apt/sources.list.d/salt.list > /dev/null
    
    # Pin to 3007
    cat <<EOF > /etc/apt/preferences.d/salt-pin-1001
Package: salt-*
Pin: version 3007.*
Pin-Priority: 1001
EOF
    
    $PKG_MGR update
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    
    log "Installing Salt Components..."
    # Install libpam0g-dev so we can build/link PAM modules
    $PKG_MGR install -y nodejs build-essential salt-master salt-minion salt-api salt-ssh libpam0g-dev
    $PKG_MGR install -y python3-cherrypy3 || pip3 install cherrypy
else
    error "No supported package manager found."
    exit 1
fi

# --- FIX FOR UBUNTU ONEDIR ---
# Salt 3007 uses a bundled Python. We MUST install 'python-pam' inside THAT environment.
if [ -f "/opt/saltstack/salt/bin/pip" ]; then
    log "Detected Salt Onedir. Installing python-pam into Salt's private Python environment..."
    /opt/saltstack/salt/bin/pip install python-pam
else
    log "Salt Onedir pip not found. Assuming system pip..."
    pip3 install python-pam
fi

log "Configuring system user '$SALT_USER'..."
if ! id "$SALT_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$SALT_USER"
fi

# Set password safely
echo "$SALT_USER:$SALT_PASS" | chpasswd
usermod -U "$SALT_USER" 2>/dev/null || true

log "Configuring Salt Master and API (Monolithic Config)..."

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

# Config update (using localhost for API to avoid bind issues)
python3 -c "
import json
import sys
config_path = '$CONFIG_FILE'
try:
    with open(config_path, 'r') as f:
        data = json.load(f)
    # Update values
    data['proxyURL'] = ''
    data['saltAPIUrl'] = 'http://127.0.0.1:$API_PORT'
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

systemctl restart salt-master salt-api salt-minion salt-gui

log "Waiting for local minion to contact master..."
sleep 5

log "Accepting local minion key..."
salt-key -y -a "salt-master-gui" || warn "Key 'salt-master-gui' not found yet. You may need to accept it in the GUI."

log "Deployment Complete!"
echo "--------------------------------------------------------"
echo "Salt-GUI Accessible at: http://$SERVER_IP:$GUI_PORT"
echo "Salt-API Accessible at: http://127.0.0.1:$API_PORT"
echo "User: $SALT_USER"
echo "Password: $SALT_PASS"
echo "--------------------------------------------------------"