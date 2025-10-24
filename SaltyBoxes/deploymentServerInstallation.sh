#!/bin/bash
#
# This script automates the installation and basic configuration of a
# SaltStack master server (master, api, minion) and a Node.js GUI.
#
# It will:
# 1. Check for root privileges.
# 2. Detect package manager and install dependencies (curl, git, nodejs, npm).
# 3. Download and execute the official Salt bootstrap script.
# 4. Configure the salt-api to run on a custom port (for Splunk).
# 5. Configure PAM eauth for the API via a 'saltapiusers' group.
# 6. Download and configure the Salt-GUI.
# 7. Create and start a systemd service for the GUI.
# 8. Enable and restart all Salt services.
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

GUI_REPO_URL="https://github.com/kyschwartz/salt-gui.git"
GUI_INSTALL_DIR="/opt/salt-gui"
GUI_SERVER_DIR="$GUI_INSTALL_DIR/Salt-GUI-master"
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
    # This command downloads the script and pipes it to sudo sh.
    # -s: Tells 'sh' to read from standard input.
    # --: A POSIX-compliant way to stop option-processing and pass
    #     the following arguments (-M -A) to the script itself.
    curl -L https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh | sudo sh -s -- -M -A
}

configure_api() {
    log "Configuring Salt API in $API_CONFIG_FILE..."
    mkdir -p /etc/salt/master.d
    touch $API_CONFIG_FILE

    # --- Configure rest_cherrypy ---
    if ! grep -q "^rest_cherrypy:" $API_CONFIG_FILE; then
        echo "rest_cherrypy:" >> $API_CONFIG_FILE
    fi

    # Set port
    sed -i "/^[ ]*port:.*/d" $API_CONFIG_FILE # Remove old port line if exists
    sed -i "/^rest_cherrypy:/a \  port: $SALT_API_PORT" $API_CONFIG_FILE
    
    # Set host
    sed -i "/^[ ]*host:.*/d" $API_CONFIG_FILE # Remove old host line
    sed -i "/^rest_cherrypy:/a \  host: 0.0.0.0" $API_CONFIG_FILE
    
    # Disable SSL
    sed -i "/^[ ]*disable_ssl:.*/d" $API_CONFIG_FILE # Remove old ssl line
    sed -i "/^rest_cherrypy:/a \  disable_ssl: True" $API_CONFIG_FILE
    warn "Salt API configured with SSL disabled (disable_ssl: True). This is not recommended for production."

    # --- Configure PAM EAuth ---
    log "Configuring PAM external auth for '@saltapiusers' group..."
    if ! grep -q "^external_auth:" $API_CONFIG_FILE; then
        cat << EOF >> $API_CONFIG_FILE

external_auth:
  pam:
    '@saltapiusers':
      - .*
EOF
    fi

    log "Creating 'saltapiusers' group. (Errors are safe if group already exists)."
    groupadd saltapiusers || true
}

install_and_configure_gui() {
    log "Setting up Salt-GUI..."
    if [ -d "$GUI_INSTALL_DIR" ]; then
        log "GUI directory $GUI_INSTALL_DIR already exists. Skipping clone."
    else
        log "Cloning Salt-GUI from $GUI_REPO_URL..."
        git clone $GUI_REPO_URL $GUI_INSTALL_DIR
    fi

    log "Installing Node.js dependencies for GUI..."
    cd $GUI_SERVER_DIR
    npm install --loglevel=error

    log "Configuring GUI to connect to local Salt API (http://127.0.0.1:$SALT_API_PORT)..."
    # Use 127.0.0.1 to avoid DNS resolution issues and connect locally
    # This replaces the hardcoded URL in the server.js file
    sed -i "s|const saltApiUrl = 'https://salt80.soc-se.org/salt-api';|const saltApiUrl = 'http://127.0.0.1:$SALT_API_PORT';|" $GUI_SERVER_JS
    
    # Check if sed worked
    if ! grep -q "http://127.0.0.1:$SALT_API_PORT" $GUI_SERVER_JS; then
        error "Failed to configure $GUI_SERVER_JS. The hardcoded URL 'https://salt80.soc-se.org/salt-api' may have changed in the repo."
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

# --- Main Execution ---

check_root
install_dependencies
run_bootstrap
configure_api
manage_salt_services
install_and_configure_gui
run_gui_background

log "---"
log "SaltStack master, API, minion, and GUI installation complete!"
log "All services have been enabled and started."
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
log "3. LOCAL MINION: Configure the local minion to talk to the master:"
log "   - Edit /etc/salt/minion and set 'master: localhost'"
log "   - Run: systemctl restart salt-minion"
log "4. ACCEPT KEY: Accept the local minion's key:"
log "   - Run: salt-key -A -y"
log "5. TEST GUI: Access the GUI in your browser at http://<this-server-ip>:3000"
log "---"