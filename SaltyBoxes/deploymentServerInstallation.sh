#!/bin/bash
#
# This script automates the installation and complete configuration of a
# SaltStack deployment server (master, api, minion) and a Node.js GUI.
#
# The Node.js GUI server runs directly on port 3000 and serves all content.
# Authentication uses the 'deployuser' account via PAM.
# Configuration for the Node.js backend is read from config.json.
#
# --- Ports Used ---
# TCP 3000: Salt-GUI Node.js Backend & Frontend (Public Access Point)
# TCP 4505: Salt Master (Publisher)
# TCP 4506: Salt Master (Returner)
# TCP 8001: Salt API (Listens on 0.0.0.0, accessed via Node.js proxy)
#

# --- Configuration ---
SALT_API_PORT=8001
NODEJS_PORT=3000 # Port the Node.js server will listen on
MASTER_CONFIG_FILE="/etc/salt/master"
MINION_CONFIG_FILE="/etc/salt/minion"

GUI_REPO_URL="https://github.com/kyschwartz/salt-gui.git"
GUI_INSTALL_DIR="/opt/salt-gui" # Use this directly for paths
GUI_CONFIG_JSON="$GUI_INSTALL_DIR/config.json" # Path to config file
GUI_SCRIPT_JS="$GUI_INSTALL_DIR/script.js"    # Path to Frontend JS script
GUI_SERVICE_FILE="/etc/systemd/system/salt-gui.service"
GUI_USER="saltgui"

# --- SECURE CREDENTIALS ---
API_USER="deployuser"
# !! IMPORTANT: CHANGE THIS DEFAULT PASSWORD !!
API_PASS="ChangeMeIntoAMuchHarderToCrackPasswordPleaseBecauseThisIsSuperShort123!*"


# Exit immediately if a command exits with a non-zero status.
set -e

# --- Helper Functions ---
log() {
    echo "[INFO] $1"
}

warn() {
    echo "[WARN] $1"
}

error() {
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

# Function to attempt to get the primary public/private IP address
get_server_ip() {
    # Try common commands to find a non-localhost IP
    local ip_addr=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d '/' -f 1 | head -n 1)
    if [ -z "$ip_addr" ]; then
        ip_addr=$(hostname -I | awk '{print $1}')
    fi
    if [ -z "$ip_addr" ]; then
        # Fallback if other methods fail
        warn "Could not automatically determine server IP. Using 'localhost'. You may need to manually edit $GUI_SCRIPT_JS."
        ip_addr="localhost"
    fi
    echo "$ip_addr"
}


install_dependencies() {
    # Removed nginx, kept jq
    log "Installing base dependencies (curl, git, jq, policycoreutils-python-utils)..."

    if command -v apt &> /dev/null; then
        log "Detected Debian-based system (apt found)."
        apt-get update -y > /dev/null
        apt-get install -y curl git jq # policycoreutils usually default/part of selinux-utils
        
        if ! command -v node &> /dev/null; then
            log "Installing Node.js (LTS) from NodeSource for Debian..."
            curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - > /dev/null
            apt-get install -y nodejs
        else
            log "Node.js already installed."
        fi
        PKG_MANAGER="apt"

    elif command -v dnf &> /dev/null; then
        log "Detected Red Hat-based system (dnf found)."
        dnf install -y curl git jq policycoreutils-python-utils # For semanage
        
        if ! command -v node &> /dev/null; then
            log "Installing Node.js (LTS) from NodeSource for RHEL (dnf)..."
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - > /dev/null
            dnf install -y nodejs
        else
            log "Node.js already installed."
        fi
        PKG_MANAGER="dnf"

    elif command -v yum &> /dev/null; then
        log "Detected Red Hat-based system (yum found)."
        # Assumes EPEL is enabled or jq is in base repos for older RHEL/CentOS
        yum install -y curl git jq policycoreutils-python-utils # For semanage
        
        if ! command -v node &> /dev/null; then
            log "Installing Node.js (LTS) from NodeSource for RHEL (yum)..."
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - > /dev/null
            yum install -y nodejs
        else
            log "Node.js already installed."
        fi
        PKG_MANAGER="yum"

    else
        error "Unsupported distribution. No 'apt', 'dnf', or 'yum' package manager found."
    fi
}

run_bootstrap() {
    log "Downloading and executing the Salt bootstrap script..."
    curl -L https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh | sh -s -- -M -A
}

ensure_api_installed() {
    log "Ensuring salt-api package is installed..."
    case "$PKG_MANAGER" in
        apt) apt-get install -y salt-api > /dev/null ;;
        dnf) dnf install -y salt-api > /dev/null ;;
        yum) yum install -y salt-api > /dev/null ;;
    esac
    log "salt-api package installation confirmed."
}

configure_api() {
    log "Configuring Salt API in $MASTER_CONFIG_FILE..."

    if grep -q "^rest_cherrypy:" $MASTER_CONFIG_FILE; then
        warn "Salt API configuration section (rest_cherrypy) already exists in $MASTER_CONFIG_FILE. Skipping append."
    else
        cat << EOF >> $MASTER_CONFIG_FILE

# --- Salt API Configuration (Auto-Generated by Script) ---
rest_cherrypy:
  port: $SALT_API_PORT
  host: 0.0.0.0
  disable_ssl: True

external_auth:
  pam:
    $API_USER:
      - .* # Permission to target all minions
      - '@runner'   # Permission to run salt-master runner functions
      - '@wheel'    # Permission to run salt-master wheel functions
      - '@jobs'     # Permssion to access the jobs system

# Also ensure netapi_enable_clients is set correctly
netapi_enable_clients:
  - local
  - runner
  - wheel
EOF
        warn "Salt API configured with SSL disabled (disable_ssl: True). This is not recommended for production."
    fi
}

configure_master_user() {
    log "CRITICAL STEP: Changing Salt Master run user to 'root' for PAM compatibility..."
    sed -i '/^#*user: /d' $MASTER_CONFIG_FILE # Remove existing 'user:' line
    echo "user: root" >> $MASTER_CONFIG_FILE # Add 'user: root' explicitly
    log "Salt Master run user set to 'root' in $MASTER_CONFIG_FILE."
}

create_api_user() {
    log "Creating/Updating system user '$API_USER' for API authentication..."
    if id "$API_USER" &>/dev/null; then
        log "User '$API_USER' already exists. Setting password."
    else
        log "Creating new system user '$API_USER'..."
        useradd -r -M $API_USER # Create system user, no home dir
    fi
    echo "$API_USER:$API_PASS" | chpasswd # Set password non-interactively
    log "API user '$API_USER' configured for PAM authentication."
}

manage_salt_services() {
    log "Enabling Salt services (master, api, minion)..."
    systemctl enable salt-master salt-api salt-minion > /dev/null

    log "Restarting Salt services to apply configuration..."
    systemctl restart salt-master
    systemctl restart salt-api
    systemctl restart salt-minion
}

install_and_configure_gui() {
    log "Setting up Salt-GUI in $GUI_INSTALL_DIR..."
    if [ -d "$GUI_INSTALL_DIR" ]; then
        log "GUI directory exists. Removing old version and re-cloning for clean install..."
        rm -rf "$GUI_INSTALL_DIR"
    fi
    
    log "Cloning Salt-GUI from $GUI_REPO_URL..."
    git clone $GUI_REPO_URL --branch=master "$GUI_INSTALL_DIR"

    log "Installing Node.js dependencies for GUI..."
    # Use GUI_INSTALL_DIR directly now
    cd "$GUI_INSTALL_DIR"
    npm install --loglevel=error # Install dependencies listed in package.json

    log "Configuring GUI backend via $GUI_CONFIG_JSON..."

    if [ ! -f "$GUI_CONFIG_JSON" ]; then
        error "$GUI_CONFIG_JSON not found after cloning. Cannot configure."
    fi

    local temp_json=$(mktemp)
    jq \
    --arg user "$API_USER" \
    --arg pass "$API_PASS" \
    --arg url "http://127.0.0.1:$SALT_API_PORT" \
    '.saltApiUrl = $url | .saltUsername = $user | .saltPassword = $pass' \
    "$GUI_CONFIG_JSON" > "$temp_json" \
    || error "jq command failed to update $GUI_CONFIG_JSON"
    mv "$temp_json" "$GUI_CONFIG_JSON" \
    || error "Failed to replace $GUI_CONFIG_JSON with updated version."

    # Verify updates
    if ! grep -q "\"saltApiUrl\": \"http://127.0.0.1:$SALT_API_PORT\"" "$GUI_CONFIG_JSON"; then
        warn "Could not verify saltApiUrl update in $GUI_CONFIG_JSON."
    fi
    if ! grep -q "\"saltUsername\": \"$API_USER\"" "$GUI_CONFIG_JSON"; then
        warn "Could not verify saltUsername update in $GUI_CONFIG_JSON."
    fi

    log "Configuring GUI frontend ($GUI_SCRIPT_JS)..."
    # Get the server IP
    local server_ip=$(get_server_ip)
    local proxy_url_for_script="http://${server_ip}:${NODEJS_PORT}"
    log "Setting frontend proxy URL to: $proxy_url_for_script"

    # Use a different delimiter for sed since the replacement contains slashes
    sed -i "s|^ *const proxyUrl = 'http://localhost:3000';|const proxyUrl = '${proxy_url_for_script}';|" "$GUI_SCRIPT_JS" \
    || error "Failed to update proxyUrl in $GUI_SCRIPT_JS"
     # Verify update
    if ! grep -q "const proxyUrl = '${proxy_url_for_script}';" "$GUI_SCRIPT_JS"; then
        warn "Failed to confirm proxyUrl update in $GUI_SCRIPT_JS. Manual edit might be needed."
    fi

    log "GUI config.json and script.js configured."
    cd - > /dev/null # Go back to previous directory
}

setup_gui_service() {
    log "Creating '$GUI_USER' user for Salt-GUI service..."
    useradd -r -M -s /bin/false -d "$GUI_INSTALL_DIR" "$GUI_USER" || log "User $GUI_USER likely already exists."
    chown -R "$GUI_USER":"$GUI_USER" "$GUI_INSTALL_DIR"

    NODE_PATH=$(which node)
    if [ -z "$NODE_PATH" ]; then
        error "Could not find 'node' executable path."
    fi
    log "Node.js executable found at $NODE_PATH"

    log "Creating systemd service file at $GUI_SERVICE_FILE..."
    cat << EOF > "$GUI_SERVICE_FILE"
[Unit]
Description=Salt-GUI Node.js Backend Server
Documentation=$GUI_REPO_URL
After=network.target salt-api.service # Depends on network and salt-api

[Service]
Type=simple
User=$GUI_USER
Group=$GUI_USER
# Use GUI_INSTALL_DIR directly
WorkingDirectory=$GUI_INSTALL_DIR 
# Server.js should read config.json for settings
# Ensure server.js listens on 0.0.0.0 or the specific IP to be accessible
ExecStart=$NODE_PATH server.js 
Restart=always
RestartSec=10
# Optional: Add environment variables if needed
# Environment="NODE_ENV=production"

[Install]
WantedBy=multi-user.target
EOF

    log "Reloading systemd, enabling and starting salt-gui service..."
    systemctl daemon-reload
    systemctl enable --now salt-gui.service
    systemctl status salt-gui --no-pager
    log "Node.js service 'salt-gui' is set up. Ensure it's listening on 0.0.0.0:$NODEJS_PORT or the server's IP."
}

configure_selinux() {
    # Only configure SELinux on Red Hat based systems
    if [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        log "Configuring SELinux..."
        
        if sestatus | grep "Current mode:" | grep -q "enforcing"; then
            log "SELinux is enforcing."
            
            # Allow node process (assuming systemd context) to listen on the specified port
            log "Allowing Node.js service to bind to port $NODEJS_PORT..."
            # Check if http_port_t already includes the port
            if ! semanage port -l | grep http_port_t | grep -qw "$NODEJS_PORT"; then
                semanage port -a -t http_port_t -p tcp "$NODEJS_PORT" || warn "Failed to add port $NODEJS_PORT to http_port_t context. GUI might be inaccessible."
            else
                log "Port $NODEJS_PORT already has http_port_t context."
            fi

            # Allow node process (assuming systemd context) to connect network ports (needed for Salt API on 8001)
            log "Allowing Node.js service network connection (daemons_enable_cluster_mode)..."
            setsebool -P daemons_enable_cluster_mode 1 || warn "Could not set daemons_enable_cluster_mode. Node.js might not reach Salt API."
            
        else
            warn "SELinux is not in enforcing mode. Skipping SELinux configuration commands."
        fi

    else
        log "Skipping SELinux configuration (not a Red Hat based system)."
    fi
}


configure_local_minion() {
    log "Configuring local salt-minion..."
    if [ ! -f "$MINION_CONFIG_FILE" ]; then
        warn "Minion config file $MINION_CONFIG_FILE not found. Skipping local minion setup."
        return
    fi
    sed -i 's/^#*master:.*/master: 127.0.0.1/' "$MINION_CONFIG_FILE" # Point minion to localhost master
    log "Restarting salt-minion..."
    systemctl restart salt-minion
    log "Waiting 5 seconds for minion key registration..."
    sleep 5
    log "Accepting all pending Salt keys..."
    salt-key -A -y || warn "salt-key command failed. Key might need manual acceptance."
}

# --- Main Execution ---

SERVER_IP=$(get_server_ip) # Get IP early for potential use/logging
log "Detected Server IP (used for frontend config): $SERVER_IP"

check_root
install_dependencies        # Includes jq now
run_bootstrap
ensure_api_installed
configure_api
configure_master_user
create_api_user
manage_salt_services      # Restart Salt services to apply changes

install_and_configure_gui # Clones repo, installs npm deps, configures config.json and script.js (using detected IP)
setup_gui_service         # Creates systemd service for Node.js app and starts it

# Configure SELinux for Node.js port and network access
configure_selinux

configure_local_minion    # Configure and accept local minion key last

log "---"
log "SaltStack Deployment Server with Salt-GUI (Node.js Direct) Setup Complete!"
log "Salt-GUI backend is configured via config.json and should be accessible on port $NODEJS_PORT."
log "Salt API user '$API_USER' is configured."
log "Local minion key should be accepted."
log "*** NGINX WAS NOT INSTALLED OR CONFIGURED ***"
log "*** FIREWALL WAS NOT CONFIGURED BY THIS SCRIPT ***"
log ""
log "--- ✅ SUCCESS: FINAL NEXT STEPS ✅ ---"
log "1. FIREWALL: Manually configure your firewall to allow TCP ports:"
log "   - $NODEJS_PORT (Salt-GUI - Public Access)"
log "   - 4505 (Salt Master Pub - If minions connect from outside)"
log "   - 4506 (Salt Master Ret - If minions connect from outside)"
log "   - $SALT_API_PORT (Salt API - Maybe only needed locally by Node.js)"
log "2. PASSWORD: If you haven't already, CHANGE THE DEFAULT '$API_USER' PASSWORD used in this script!"
log "   Run: 'sudo passwd $API_USER'"
log "   Then UPDATE the password in $GUI_CONFIG_JSON and restart the salt-gui service: 'sudo systemctl restart salt-gui'"
log "3. TEST GUI: Access the GUI in your browser at http://$SERVER_IP:$NODEJS_PORT"
log "4. TEST SALT: Run 'sudo salt '*' test.ping' on the server's command line."
log "5. CLOUD PROVIDER FW: Ensure your cloud provider/external firewall allows traffic to TCP port $NODEJS_PORT."
log "---"