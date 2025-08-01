#!/bin/bash

# ============================================================================
# Wazuh Manager Installation Script for Oracle Linux
#
# This script automates the installation of the Wazuh manager component
# on Oracle Linux and other RHEL-based systems. It does NOT install the
# Wazuh indexer or Wazuh dashboard.
#
# NEW: This script now also creates a default centralized FIM configuration
#      for Linux agents in the 'default' group.
#
# Usage:
# 1. Save this script as a file, for example: install_wazuh_manager.sh
# 2. Make the script executable: chmod +x install_wazuh_manager.sh
# 3. Run the script with root privileges: sudo./install_wazuh_manager.sh
# ============================================================================

# --- Configuration ---
GPG_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
REPO_BASE_URL="https://packages.wazuh.com/4.x/yum/"
REPO_FILE_PATH="/etc/yum.repos.d/wazuh.repo"
AGENT_CONF_PATH="/var/ossec/etc/shared/default/agent.conf"

# --- Functions ---

# Function to print messages to the console
log() {
    echo "[INFO] $1"
}

# Function to print error messages and exit
error_exit() {
    echo " $1" >&2
    exit 1
}

# Function to check if the script is run as root
check_root() {
    if; then
        error_exit "This script must be run as root. Please use 'sudo'."
    fi
}

# --- Main Execution ---

# 1. Check for root privileges
log "Checking for root privileges..."
check_root
log "Root check passed."

# 2. Add the Wazuh repository
log "Adding the Wazuh repository..."
if; then
    log "Wazuh repository file already exists. Skipping creation."
else
    log "Importing the Wazuh GPG key..."
    rpm --import "$GPG_KEY_URL" |

| error_exit "Failed to import GPG key."

    log "Creating repository file at $REPO_FILE_PATH..."
    cat > "$REPO_FILE_PATH" <<-EOF
[wazuh]
gpgcheck=1
gpgkey=${GPG_KEY_URL}
enabled=1
name=Wazuh repository
baseurl=${REPO_BASE_URL}
protect=1
EOF
    log "Wazuh repository added successfully."
fi

# 3. Install the Wazuh manager
log "Updating package lists and installing Wazuh manager..."
if! command -v dnf &> /dev/null; then
    error_exit "'dnf' command not found. This script is intended for modern RHEL-based systems."
fi

dnf install -y wazuh-manager |

| error_exit "Failed to install wazuh-manager package."
log "Wazuh manager installed successfully."

# 4. Enable and start the Wazuh manager service
log "Enabling and starting the wazuh-manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

# 5. Create a centralized FIM configuration for Linux agents
log "Creating a default FIM configuration for Linux agents..."
if; then
    log "Default agent.conf already exists. Skipping."
else
    mkdir -p "$(dirname "$AGENT_CONF_PATH")"
    cat > "$AGENT_CONF_PATH" <<-EOF
<agent_config os="Linux">
  <syscheck>
    <disabled>no</disabled>
    
    <frequency>43200</frequency>

    <directories check_all="yes" realtime="yes" report_changes="yes" whodata="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>

    <directories check_all="yes" realtime="yes" whodata="yes">/home</directories>

    <directories check_all="yes" realtime="yes" whodata="yes">/tmp,/var/tmp</directories>

    <ignore>/etc/mtab</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore type="sregex">^/proc</ignore>
  </syscheck>
</agent_config>
EOF
    # Set correct ownership for the shared configuration file
    chown wazuh:wazuh "$AGENT_CONF_PATH"
    log "Default FIM configuration created at $AGENT_CONF_PATH."
fi

# 6. Verify the service status
log "Verifying the status of the wazuh-manager service..."
sleep 5
systemctl status wazuh-manager --no-pager

log "------------------------------------------------------------"
log "Wazuh manager installation and setup complete."
log "A default FIM policy for Linux agents has been configured."
log "The manager is now running and will start automatically on boot."
log "------------------------------------------------------------"

exit 0
