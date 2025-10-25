#!/bin/bash
#
# This script automates the installation and complete configuration of a
# SaltStack deployment server (master, api, minion) and a Node.js GUI.
#
# It will:
# 1. Check for root privileges.
# 2. Detect package manager and install dependencies (curl, git, nodejs, npm).
# 3. Download and execute the official Salt bootstrap script.
# 4. Force install salt-api to ensure it's present.
# 5. Configure the salt-api to run on custom port 8001.
# 6. **CRITICAL FIX: Change Salt Master run user to 'root' for PAM compatibility.**
# 7. Configure PAM eauth for the API via a 'saltapiusers' group.
# 8. Create the 'deployuser' API access user.
# 9. Download, configure credentials, and install dependencies for the Salt-GUI.
# 10. Create and start a systemd service for the GUI.
# 11. Configure the local minion and accept its key.
#
# --- Ports Used ---
# TCP 3000: Salt-GUI Web Interface
# TCP 4505: Salt Master (Publisher)
# TCP 4506: Salt Master (Returner)
# TCP 8001: Salt API (Custom port to avoid Splunk)
#

# --- Configuration ---
SALT_API_PORT=8001
API_CONFIG_FILE="/etc/salt/master.d/api.conf"
MINION_CONFIG_FILE="/etc/salt/minion"

GUI_REPO_URL="https://github.com/kyschwartz/salt-gui.git"
GUI_INSTALL_DIR="/opt/salt-gui"
# Correct path after git clone creates 'Salt-GUI-master' folder inside install dir
GUI_SERVER_DIR="$GUI_INSTALL_DIR/"
GUI_SERVER_JS="$GUI_SERVER_DIR/server.js"
GUI_SERVICE_FILE="/etc/systemd/system/salt-gui.service"
GUI_USER="saltgui"

# --- SECURE CREDENTIALS ---
API_USER="deployuser"
API_PASS="ChangeMeIntoAMuchHarderToCrackPasswordPleaseBecauseThisIsSuperShort123!*"


# Exit immediately if a command exits with a non-zero status.
set -e

# --- Helper Functions ---
log() {
    # Logs a message to stdout
    echo "[INFO] $1"
}

warn() {
    # Logs a warning message to stdout
    echo "[WARN] $1"
}

error() {
    # Logs an error message to stderr and exits
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Script Functions ---

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root or with sudo."
    fi
    log "Root privileges confirmed."
}

install_dependencies() {
    log "Installing base dependencies (curl, git)..."
    
    if command -v apt &> /dev/null; then
        log "Detected Debian-based system (apt found)."
        apt-get update -y > /dev/null
        apt-get install -y curl git
        
        if ! command -v node &> /dev/null; then
            log "Installing Node.js (LTS) from NodeSource for Debian..."
            curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo bash - > /dev/null
            apt-get install -y nodejs
        else
            log "Node.js already installed."
        fi
        
    elif command -v dnf &> /dev/null; then
        log "Detected Red Hat-based system (dnf found)."
        dnf install -y curl git
        
        if ! command -v node &> /dev/null; then
            log "Installing Node.js (LTS) from NodeSource for RHEL (dnf)..."
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash - > /dev/null
            dnf install -y nodejs
        else
            log "Node.js already installed."
        fi
        
    elif command -v yum &> /dev/null; then
        log "Detected Red Hat-based system (yum found)."
        yum install -y curl git
        
        if ! command -v node &> /dev/null; then
            log "Installing Node.js (LTS) from NodeSource for RHEL (yum)..."
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash - > /dev/null
            yum install -y nodejs
        else
            log "Node.js already installed."
        fi
        
    else
        error "Unsupported distribution. No 'apt', 'dnf', or 'yum' package manager found."
    fi
}

run_bootstrap() {
    log "Downloading and executing the Salt bootstrap script..."
    curl -L https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh | sudo sh -s -- -M -A
}

ensure_api_installed() {
    log "Ensuring salt-api package is installed..."
    if command -v apt &> /dev/null; then
        apt-get install -y salt-api > /dev/null
    elif command -v dnf &> /dev/null; then
        dnf install -y salt-api > /dev/null
    elif command -v yum &> /dev/null; then
        yum install -y salt-api > /dev/null
    fi
    log "salt-api package installation confirmed."
}

configure_api() {
    log "Configuring Salt API in $API_CONFIG_FILE..."
    mkdir -p /etc/salt/master.d
    touch $API_CONFIG_FILE

    # Clear the file to prevent duplicate entries from script re-runs
    > $API_CONFIG_FILE

    # --- Configure rest_cherrypy ---
    cat << EOF >> $API_CONFIG_FILE
rest_cherrypy:
  port: $SALT_API_PORT
  host: 0.0.0.0
  disable_ssl: True
EOF

    warn "Salt API configured with SSL disabled (disable_ssl: True). This is not recommended for production."

    # --- Configure PAM EAuth ---
    log "Configuring PAM external auth for '@saltapiusers' group..."
    cat << 'EOF' >> $API_CONFIG_FILE

external_auth:
  pam:
    '@saltapiusers':
      - .*
EOF

    log "Creating 'saltapiusers' group. (Errors are safe if group already exists)."
    groupadd saltapiusers || true
}

# *** NEW FUNCTION ADDED ***
configure_master_user() {
    log "CRITICAL STEP: Changing Salt Master run user to 'root' for PAM compatibility..."
    # The default config has the line: #user: salt. This removes any existing 'user:' line and inserts the 'user: root' line.
    sed -i '/^#*user: /d' /etc/salt/master
    echo "user: root" >> /etc/salt/master
    log "Salt Master run user set to 'root' in /etc/salt/master."
}

create_api_user() {
    log "Creating API user '$API_USER' for GUI..."
    if id "$API_USER" &>/dev/null; then
        log "User '$API_USER' already exists. Ensuring they are in 'saltapiusers' group."
        usermod -a -G saltapiusers $API_USER
    else
        log "Creating new system user '$API_USER'..."
        useradd -r -M -G saltapiusers $API_USER
    fi
    
    log "Setting password for '$API_USER'..."
    echo "$API_USER:$API_PASS" | chpasswd
    
    log "API user '$API_USER' is configured."
}

install_and_configure_gui() {
    log "Setting up Salt-GUI..."
    if [ -d "$GUI_INSTALL_DIR" ]; then
        log "GUI directory $GUI_INSTALL_DIR already exists. Skipping clone."
    else
        log "Cloning Salt-GUI from $GUI_REPO_URL..."
        git clone $GUI_REPO_URL --branch=master $GUI_INSTALL_DIR
    fi

    log "Installing Node.js dependencies for GUI..."
    cd $GUI_SERVER_DIR
    # This was commented out, but is necessary for the node app to run
    npm install --loglevel=error

    log "Configuring GUI to use new credentials and local API..."
    
    # --- SED COMMANDS to update credentials and URL ---
    # Need to escape the password for sed, using printf %q for reliable shell quoting
    local escaped_pass=$(printf '%q' "$API_PASS" | sed 's/\\!/!/g; s/\\\*/\*/g')

    # 1. Update Username
    if ! sed -i "s/username: 'sysadmin',/username: '$API_USER',/" $GUI_SERVER_JS; then
        error "sed command failed to update username in $GUI_SERVER_JS"
    fi
    
    # 2. Update Password
    if ! sed -i "s/password: 'Changeme1!',/password: '$escaped_pass',/" $GUI_SERVER_JS; then
        error "sed command failed to update password in $GUI_SERVER_JS"
    fi

    # 3. Update API URL
    local find_string="^const saltApiUrl = 'https://salt80.soc-se.org/salt-api'.*"
    local replace_string="const saltApiUrl = 'http://127.0.0.1:$SALT_API_PORT';"
    
    if ! sed -i "s|$find_string|$replace_string|" $GUI_SERVER_JS; then
        error "sed command failed to update API URL in $GUI_SERVER_JS"
    fi
    
    # Final check on URL
    if ! grep -q "http://127.0.0.1:$SALT_API_PORT" $GUI_SERVER_JS; then
        error "Failed to confirm API URL update in $GUI_SERVER_JS."
    fi
    
    log "The Salt-GUI server.js file is now configured to use '$API_USER'."
}

run_gui_background() {
    log "Creating '$GUI_USER' user for Salt-GUI service..."
    useradd -r -M -s /bin/false -d $GUI_INSTALL_DIR $GUI_USER || true
    chown -R $GUI_USER:$GUI_USER $GUI_INSTALL_DIR

    NODE_PATH=$(which node)
    if [ -z "$NODE_PATH" ]; then
        error "Could not find 'node' executable path."
    fi
    log "Node.js executable found at $NODE_PATH"

    log "Creating systemd service file at $GUI_SERVICE_FILE..."
    cat << EOF > $GUI_SERVICE_FILE
[Unit]
Description=Salt-GUI Node.js Web Server
Documentation=$GUI_REPO_URL
After=network.target salt-api.service

[Service]
Type=simple
User=$GUI_USER
Group=$GUI_USER
WorkingDirectory=$GUI_SERVER_DIR
ExecStart=$NODE_PATH server.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    log "Reloading systemd, enabling and starting salt-gui service..."
    systemctl daemon-reload
    systemctl enable --now salt-gui.service
}

manage_salt_services() {
    log "Enabling Salt services to start on boot..."
    systemctl enable salt-master
    systemctl enable salt-api
    systemctl enable salt-minion

    log "Restarting all Salt services to apply configuration..."
    # salt-master restart is critical to pick up the 'user: root' change
    systemctl restart salt-master
    systemctl restart salt-api
    systemctl restart salt-minion
}

configure_local_minion() {
    log "Configuring local salt-minion..."
    if [ ! -f "$MINION_CONFIG_FILE" ]; then
        warn "Minion config file $MINION_CONFIG_FILE not found. Skipping local minion setup."
        return
    fi
    
    # This finds any line starting with '#master:' or 'master:' and replaces it
    sed -i 's/^#*master:.*/master: localhost/' $MINION_CONFIG_FILE
    
    log "Restarting salt-minion to apply new config..."
    systemctl restart salt-minion
    
    log "Waiting 5 seconds for minion to register key..."
    sleep 5
    
    log "Accepting all pending keys (including local minion)..."
    salt-key -A -y
}

# --- Main Execution ---

check_root
install_dependencies
run_bootstrap
ensure_api_installed
configure_api
configure_master_user   # <-- CRITICAL FIX ADDED HERE
create_api_user
manage_salt_services
install_and_configure_gui
run_gui_background
configure_local_minion

log "---"
log "SaltStack master, API, minion, and GUI installation complete!"
log "The Salt Master is now configured for PAM authentication."
log "The API user '$API_USER' has been created."
log "The local minion key has been automatically accepted."
log ""
log "--- IMPORTANT NEXT STEPS ---"
log "1. FIREWALL: Manually configure your firewall to allow TCP ports:"
log "   - $SALT_API_PORT (Salt API)"
log "   - 4505 (Salt Master Pub)"
log "   - 4506 (Salt Master Ret)"
log "   - 3000 (Salt-GUI)"
log "2. TEST GUI: Access the GUI in your browser at http://<this-server-ip>:3000"
log "3. TEST SALT: Run 'salt '*' test.ping'"
log "---"