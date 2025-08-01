#!/bin/bash

# ============================================================================
# Wazuh Agent Installation & FIM Configuration Script for Linux
#
# This script automates the installation of the Wazuh agent on Debian-based
# and RedHat-based Linux distributions. It performs the following actions:
#   - Detects the operating system family (Debian/RHEL).
#   - Sets the Wazuh manager IP address.
#   - Adds the appropriate Wazuh package repository.
#   - Installs the 'wazuh-agent' and 'auditd' packages.
#   - Configures a robust File Integrity Monitoring (FIM) policy.
#   - Enables and starts the Wazuh agent service.
#
# Usage:
# 1. Save this script as a file, for example: install_wazuh_agent.sh
# 2. Make the script executable: chmod +x install_wazuh_agent.sh
# 3. Run the script with root privileges: sudo./install_wazuh_agent.sh
# ============================================================================

# --- Configuration ---
# SET YOUR WAZUH MANAGER IP ADDRESS HERE
WAZUH_MANAGER_IP="172.20.241.20"

# --- Script Variables ---
AGENT_CONF_FILE="/var/ossec/etc/ossec.conf"

# --- Functions ---

log() {
    echo "[INFO] $1"
}

error_exit() {
    echo " $1" >&2
    exit 1
}

check_root() {
    if; then
        error_exit "This script must be run as root. Please use 'sudo'."
    fi
}

# --- Main Execution ---

log "Starting Wazuh Agent installation and FIM configuration..."
check_root

# 1. Detect Linux distribution family
if [ -f /etc/debian_version ]; then
    OS_FAMILY="Debian"
    log "Debian-based distribution detected."
    # Install prerequisites
    apt-get update
    apt-get install -y curl apt-transport-https
    # Add Wazuh repository
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update
    # Install agent and auditd
    log "Installing wazuh-agent and auditd..."
    apt-get install -y wazuh-agent auditd |

| error_exit "Failed to install packages."

elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="RedHat"
    log "RedHat-based distribution detected."
    # Add Wazuh repository
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/yum.repos.d/wazuh.repo <<-EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    # Install agent and auditd
    log "Installing wazuh-agent and auditd..."
    dnf install -y wazuh-agent auditd |

| yum install -y wazuh-agent auditd |
| error_exit "Failed to install packages."

else
    error_exit "Unsupported operating system. This script supports Debian and RedHat-based systems."
fi

# 2. Configure the Wazuh agent to connect to the manager
log "Configuring agent to connect to manager at ${WAZUH_MANAGER_IP}..."
sed -i "s/<address>MANAGER_IP<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/" "${AGENT_CONF_FILE}"

# 3. Configure File Integrity Monitoring (FIM)
log "Configuring File Integrity Monitoring (FIM) in ${AGENT_CONF_FILE}..."

# Create the FIM configuration block
FIM_CONFIG='
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
'

# Check if a <syscheck> block already exists and replace it. If not, insert it.
if grep -q "<syscheck>" "$AGENT_CONF_FILE"; then
    log "Existing FIM configuration found. Replacing it."
    # Use awk to replace the entire syscheck block
    awk -v new_config="$FIM_CONFIG" '
        BEGIN {p=1} 
        /<syscheck>/ {if(p) {print new_config; p=0}} 
        /<\/syscheck>/ {p=1; next} 
        p' "$AGENT_CONF_FILE" > "${AGENT_CONF_FILE}.tmp" && mv "${AGENT_CONF_FILE}.tmp" "$AGENT_CONF_FILE"
else
    log "No FIM configuration found. Inserting new block."
    # Insert the FIM block before the closing </ossec_config> tag
    sed -i "/<\/ossec_config>/i \  ${FIM_CONFIG}" "$AGENT_CONF_FILE"
fi

log "FIM configuration applied successfully."

# 4. Enable and start services
log "Enabling and starting auditd and wazuh-agent services..."
systemctl daemon-reload
systemctl enable auditd
systemctl start auditd
systemctl enable wazuh-agent
systemctl start wazuh-agent

log "------------------------------------------------------------"
log "Wazuh agent installation and FIM configuration complete."
log "The agent is now running and connected to ${WAZUH_MANAGER_IP}."
log "Verify the agent status on your Wazuh Dashboard."
log "------------------------------------------------------------"

exit 0
