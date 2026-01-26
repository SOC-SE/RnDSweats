#!/bin/bash
set -euo pipefail

# ==============================================================================
# Wazuh Group and Configuration Automation Script (Multi-Group Ready)
#
# Description:
# This script automates the process of creating multiple Wazuh agent groups and
# applying specific configuration files to them. It is designed to be run on a
# Wazuh manager node.
#
# Actions Performed:
# 1. Checks for root privileges.
# 2. Iterates through a defined list of groups and their corresponding files.
# 3. Verifies the existence of the local configuration file for each group.
# 4. Checks if the Wazuh agent group already exists.
# 5. Creates the group if it does not exist.
# 6. Copies the local configuration file to the group's shared directory.
# 7. Sets the correct ownership and permissions for the configuration file.
# 8. Prompts for a Wazuh manager restart.
#
# Usage:
# 1. Place this script in the same directory as your configuration files:
#    'linux-default.conf' and 'windows-default.conf'.
# 2. Make the script executable: chmod +x setup_wazuh_groups.sh
# 3. Run the script with root privileges: sudo ./setup_wazuh_groups.sh
#
# ==============================================================================

# --- Configuration Variables ---
# Define groups and their local configuration files in a list (Group:File).
# Add more entries here to configure additional groups.
GROUPS=(
    "linux-default:linux-default.conf"
    "windows-default:windows-default.conf"
)

# --- System Variables (Do not modify unless your installation is non-standard) ---
WAZUH_PATH="/var/ossec"
AGENT_GROUPS_TOOL="${WAZUH_PATH}/bin/agent_groups"
SHARED_CONF_DIR="${WAZUH_PATH}/etc/shared"

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

# Core function to handle a single group's configuration
configure_wazuh_group() {
    local GROUP_NAME=$1
    local LOCAL_CONF_FILE=$2

    # Derived variables for the current group
    local GROUP_CONF_DIR="${SHARED_CONF_DIR}/${GROUP_NAME}"
    local GROUP_AGENT_CONF="${GROUP_CONF_DIR}/agent.conf"

    log_info "--- Starting Configuration for Group: '${GROUP_NAME}' (Using ${LOCAL_CONF_FILE}) ---"

    # 1. Verify Local Configuration File Exists
    log_info "Looking for configuration file: '${LOCAL_CONF_FILE}'..."
    if [ ! -f "${LOCAL_CONF_FILE}" ]; then
        log_error "Configuration file not found. Make sure '${LOCAL_CONF_FILE}' is in the same directory as this script. Cannot proceed with group '${GROUP_NAME}'."
        # Note: log_error exits the script entirely if the file for a critical group is missing.
    fi
    log_success "Local configuration file found."

    # 2. Check/Create Wazuh Group
    log_info "Checking if group '${GROUP_NAME}' already exists..."
    if ${AGENT_GROUPS_TOOL} -l | grep -q "^${GROUP_NAME}$"; then
        log_info "Group '${GROUP_NAME}' already exists. Proceeding to update configuration."
    else
        # Create the Group
        log_info "Group '${GROUP_NAME}' not found. Creating it now..."
        if ! ${AGENT_GROUPS_TOOL} -a -g "${GROUP_NAME}"; then
            log_error "Failed to create the Wazuh group '${GROUP_NAME}'. Please check Wazuh logs."
        fi
        log_success "Successfully created group '${GROUP_NAME}'."
    fi

    # 3. Copy Configuration File
    log_info "Applying configuration from '${LOCAL_CONF_FILE}' to group '${GROUP_NAME}'..."
    # Ensure the target directory exists
    mkdir -p "${GROUP_CONF_DIR}"
    # Copy the file to the required 'agent.conf' name within the group directory
    if ! cp "${LOCAL_CONF_FILE}" "${GROUP_AGENT_CONF}"; then
        log_error "Failed to copy configuration file for group '${GROUP_NAME}'."
    fi
    log_success "Configuration file copied to '${GROUP_AGENT_CONF}'."

    # 4. Set Ownership and Permissions
    log_info "Setting correct ownership and permissions for '${GROUP_NAME}'..."
    # Set ownership to wazuh:wazuh
    chown -R wazuh:wazuh "${GROUP_CONF_DIR}"
    # Set directory permissions to 750 and file permissions to 640.
    chmod 750 "${GROUP_CONF_DIR}"
    chmod 640 "${GROUP_AGENT_CONF}"
    log_success "Permissions set correctly for group '${GROUP_NAME}'."

    echo # Blank line for separation
}

# --- Main Script Logic ---

# 1. Check for Root Privileges
log_info "Checking for root privileges..."
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Please use sudo."
fi
log_success "Root privileges confirmed."

# 2. Loop through the groups and configure them
for GROUP_ENTRY in "${GROUPS[@]}"; do
    # Extract Group Name and Configuration File Name from the entry (e.g., 'linux-default:linux-default.conf')
    GROUP_NAME="${GROUP_ENTRY%%:*}"
    LOCAL_CONF_FILE="${GROUP_ENTRY#*:}"

    # Execute the configuration logic for the current group
    configure_wazuh_group "$GROUP_NAME" "$LOCAL_CONF_FILE"
done

# 3. Final Restart Instruction
echo
log_success "All Wazuh groups are configured. Wazuh-manager must be restarted for changes to take place across all groups."
log_info "Run: systemctl restart wazuh-manager"
