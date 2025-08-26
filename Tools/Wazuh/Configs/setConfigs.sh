#!/bin/bash

# ==============================================================================
# Wazuh Group and Configuration Automation Script
#
# Description:
# This script automates the process of creating a Wazuh agent group and
# applying a specific configuration file to it. It is designed to be run on a
# Wazuh manager node.
#
# Actions Performed:
# 1. Checks for root privileges.
# 2. Verifies the existence of the local configuration file.
# 3. Checks if the specified Wazuh agent group already exists.
# 4. Creates the group if it does not exist.
# 5. Copies the local configuration file to the group's shared directory.
# 6. Sets the correct ownership and permissions for the configuration file.
# 7. Restarts the Wazuh manager to apply the changes.
#
# Usage:
# 1. Place this script in the same directory as your 'linux-default.conf' file.
# 2. Make the script executable: chmod +x setup_wazuh_group.sh
# 3. Run the script with root privileges: sudo ./setup_wazuh_group.sh
#
# ==============================================================================

# --- Configuration Variables ---
# The name of the Wazuh agent group you want to create or manage.
GROUP_ONE_NAME="linux-default"
# The name of the local configuration file to be applied to the group.
# This file MUST be in the same directory as this script.
LOCAL_CONF_FILE="linux-default.conf"

# --- System Variables (Do not modify unless your installation is non-standard) ---
WAZUH_PATH="/var/ossec"
AGENT_GROUPS_TOOL="${WAZUH_PATH}/bin/agent_groups"
SHARED_CONF_DIR="${WAZUH_PATH}/etc/shared"
GROUP_CONF_DIR="${SHARED_CONF_DIR}/${GROUP_ONE_NAME}"
GROUP_AGENT_CONF="${GROUP_CONF_DIR}/agent.conf"

# --- Script Functions ---

# Function to print a formatted info message
log_info() {
    echo "[INFO] $1"
}

# Function to print a formatted success message
log_success() {
    echo "[SUCCESS] $1"
}

# Function to print a formatted error message and exit
log_error() {
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Main Script Logic ---

# 1. Check for Root Privileges
log_info "Checking for root privileges..."
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Please use sudo."
fi
log_success "Root privileges confirmed."

# 2. Verify Local Configuration File Exists
log_info "Looking for configuration file: '${LOCAL_CONF_FILE}'..."
if [ ! -f "${LOCAL_CONF_FILE}" ]; then
    log_error "Configuration file not found. Make sure '${LOCAL_CONF_FILE}' is in the same directory as this script."
fi
log_success "Local configuration file found."

# 3. Check if Wazuh Group Exists
log_info "Checking if group '${GROUP_ONE_NAME}' already exists..."
if ${AGENT_GROUPS_TOOL} -l | grep -q "^${GROUP_ONE_NAME}$"; then
    log_info "Group '${GROUP_NAME}' already exists. Proceeding to update configuration."
else
    # 4. Create the Group
    log_info "Group '${GROUP_ONE_NAME}' not found. Creating it now..."
    ${AGENT_GROUPS_TOOL} -a -g "${GROUP_ONE_NAME}"
    if [ $? -ne 0 ]; then
        log_error "Failed to create the Wazuh group '${GROUP_ONE_NAME}'. Please check Wazuh logs."
    fi
    log_success "Successfully created group '${GROUP_ONE_NAME}'."
fi

# 5. Copy Configuration File
log_info "Applying configuration from '${LOCAL_CONF_FILE}' to group '${GROUP_ONE_NAME}'..."
# Ensure the target directory exists
mkdir -p "${GROUP_CONF_DIR}"
# Copy the file
cp "${LOCAL_CONF_FILE}" "${GROUP_AGENT_CONF}"
if [ $? -ne 0 ]; then
    log_error "Failed to copy configuration file."
fi
log_success "Configuration file copied to '${GROUP_AGENT_CONF}'."

# 6. Set Ownership and Permissions
log_info "Setting correct ownership and permissions..."
# Set ownership to wazuh:wazuh, which is standard for recent versions.
# Change to ossec:ossec if you have an older installation.
chown -R wazuh:wazuh "${GROUP_CONF_DIR}"
# Set directory permissions to 750 and file permissions to 640.
chmod 750 "${GROUP_CONF_DIR}"
chmod 640 "${GROUP_AGENT_CONF}"
log_success "Permissions set correctly."

# 7. Restart Wazuh Manager
log_info "Restarting the Wazuh manager to apply changes..."
systemctl restart wazuh-manager
if [ $? -ne 0 ]; then
    log_error "Failed to restart the wazuh-manager service. Please check its status with 'systemctl status wazuh-manager'."
fi
log_success "Wazuh manager restarted successfully."

echo
log_success "Wazuh group '${GROUP_ONE_NAME}' is configured and ready."
