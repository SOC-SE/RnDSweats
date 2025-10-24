#!/bin/bash
#
# This script automates the installation and basic configuration of a
# SaltStack master server (master, api, minion) and a Node.js GUI.
#
# It will:
# 1. Check for root privileges.
# 2. Detect package manager and install dependencies (curl, git, nodejs, npm).
# 3. Download and execute the official Salt bootstrap script.
# 4. Force install salt-api to ensure it's present.
# 5. Configure the salt-api to run on a custom port (for Splunk).
# 6. Configure PAM eauth for the API via a 'saltapiusers' group.
# 7. Download and configure the Salt-GUI.
# 8. Create and start a systemd service for the GUI.
# 9. Enable and restart all Salt services.
# 10. Configure the local minion and accept its key.
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
GUI_SERVER_DIR="$GUI_INSTALL_DIR/"
GUI_SERVER_JS="$GUI_SERVER_DIR/server.js"
GUI_SERVICE_FILE="/etc/systemd/system/salt-gui.service"
GUI_USER="saltgui"


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
    # -M = Install Master, -A = Install API
    # We will also manually install salt-api just in case this fails.
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
    # Using the correct YAML format (no indentation on first line)
    cat << 'EOF' >> $API_CONFIG_FILE

external_auth:
  pam:
    '@saltapiusers':
      - .*
EOF

    log "Creating 'saltapiusers' group. (Errors are safe if group already exists)."
    groupadd saltapiusers || true
}

install_and_configure_gui() {
    log "Setting up Salt-GUI..."
    if [ -d "$GUI_INSTALL_DIR" ]; then
        log "GUI directory $GUI_INSTALL_DIR already exists. Skipping clone."
    else
        log "Cloning Salt-GUI from $GUI_REPO_URL..."
        git clone $GUI_REPO_URL --branch=master $GUI_INSTALL_DIR
    fi

    cd $GUI_SERVER_DIR

    log "Configuring GUI to connect to local Salt API (http://127.0.0.1:$SALT_API_PORT)..."
    
    local find_string="^const saltApiUrl = 'https://salt80.soc-se.org/salt-api'.*"
    local replace_string="const saltApiUrl = 'http://127.0.0.1:$SALT_API_PORT';"
    
    if ! sed -i "s|$find_string|$replace_string|" $GUI_SERVER_JS; then
        error "sed command failed to update $GUI_SERVER_JS"
    fi
    
    # Check if sed worked
    if ! grep -q "http://127.0.0.1:$SALT_API_PORT" $GUI_SERVER_JS; then
        error "Failed to configure $GUI_SERVER_JS. The replacement string was not found after sed."
    fi
    
    warn "The Salt-GUI server.js file has hardcoded credentials: (username: 'sysadmin', password: 'Changeme1!')."
    warn "Ensure this matches a valid PAM user in the 'saltapiusers' group."
}

run_gui_background() {
    log "Creating '$GUI_USER' user for Salt-GUI service..."
    # Create a system user (-r) with no home dir (-M) and shell (-s /bin/false)
    useradd -r -M -s /bin/false -d $GUI_INSTALL_DIR $GUI_USER || true
    chown -R $GUI_USER:$GUI_USER $GUI_INSTALL_DIR

    # Find node path
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
    systemctl restart salt-master
    systemctl restart salt-api
    systemctl restart salt-minion
}

# *** NEW FUNCTION ***
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
manage_salt_services
install_and_configure_gui
run_gui_background
configure_local_minion  # <-- NEW STEP ADDED HERE

log "---"
log "SaltStack master, API, minion, and GUI installation complete!"
log "All services have been enabled and started."
log "The local minion key has been automatically accepted."
log ""
log "--- IMPORTANT NEXT STEPS ---"
log "1. FIREWALL: Manually configure your firewall to allow TCP ports:"
log "   - $SALT_API_PORT (Salt API)"
log "   - 4505 (Salt Master Pub)"
log "   - 4506 (Salt Master Ret)"
log "   - 3000 (Salt-GUI)"
log "2. API USER: The GUI is hardcoded to use 'sysadmin' / 'Changeme1!'. Create this user:"
log "   Example: useradd -r -M -G saltapiusers sysadmin && passwd sysadmin"
log "   (When prompted, set the password to 'Changeme1!')"
log "3. TEST GUI: Access the GUI in your browser at http://<this-server-ip>:3000"
log "---"