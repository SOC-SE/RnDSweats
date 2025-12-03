#!/bin/bash

# ============================================================================
# Universal Wazuh Agent Installation Script
#
# This script automatically detects the Linux distribution (Debian-based or
# Red Hat-based), installs the Wazuh agent, and registers it with a
# predefined Wazuh manager.
#
# Manager IP is hardcoded. No registration password is used.
#
# Supported OS Families:
#   - Debian (e.g., Debian, Ubuntu)
#   - Red Hat (e.g., RHEL, CentOS, Oracle Linux, Fedora, Rocky Linux)
# ============================================================================

# --- Configuration ---
WAZUH_MANAGER_IP="172.20.242.20"
WAZUH_AGENT_GROUP_NAME="linux-default"
LOG_FILE="/var/log/wazuh_agent_installer.log"

# --- Utility Functions ---

# Function to print messages to stdout and the log file
log_msg() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

info() {
    log_msg "[INFO] $1"
}

error() {
    log_msg "[ERROR] $1" >&2
    exit 1
}

# Function to check if the last command was successful
check_success() {
    if [ $? -ne 0 ]; then
        error "The last command failed. See $LOG_FILE for details. Exiting."
    fi
}

# --- Installation Functions ---

# Function to install the Wazuh agent on Red Hat-based systems
install_on_rhel() {
    info "Detected Red Hat-based distribution."
    
    info "Adding the Wazuh YUM repository..."
    cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    check_success

    info "Installing the Wazuh agent package..."
    if command -v dnf &> /dev/null; then
        WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP_NAME" dnf install -y wazuh-agent
    else
        WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP_NAME" yum install -y wazuh-agent
    fi
    check_success
}

# Function to install the Wazuh agent on Debian-based systems
install_on_debian() {
    info "Detected Debian-based distribution."

    info "Installing prerequisites..."
    apt-get update
    apt-get install -y curl apt-transport-https lsb-release gnupg2
    check_success

    info "Adding the Wazuh GPG key..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    check_success

    info "Adding the Wazuh APT repository..."
    cat > /etc/apt/sources.list.d/wazuh.list <<EOF
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF
    check_success

    info "Installing the Wazuh agent package..."
    apt-get update
    WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP_NAME" apt-get install -y wazuh-agent
    check_success
}

# Function to enable and start the Wazuh agent service
finalize_installation() {
    info "Enabling and starting the wazuh-agent service..."
    systemctl daemon-reload
    check_success
    systemctl enable wazuh-agent
    check_success
    systemctl start wazuh-agent
    check_success

    info "Waiting for the service to initialize..."
    sleep 10

    if systemctl is-active --quiet wazuh-agent; then
        info "✔ OK: The wazuh-agent service is active and running."
    else
        error "The wazuh-agent service failed to start. Check the logs with 'journalctl -u wazuh-agent'."
    fi
}


configure_yara() {
    echo "Configuring the Yara rules"
    cp Wazuh/activeResponses/yara.sh /var/ossec/active-response/bin/yara.sh
     chown root:wazuh /var/ossec/active-response/bin/yara.sh
     chown -R root:wazuh /opt/yara-rules
     chmod 750 /var/ossec/active-response/bin/yara.sh

    mkdir /tmp/quarantined
}

# --- Main Execution ---
main() {
    # Start logging
    rm -f "$LOG_FILE"
    info "Starting Wazuh Agent Universal Installer..."

    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root."
    fi

    # Detect the distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_FAMILY=$ID_LIKE
        if [ -z "$OS_FAMILY" ]; then
            OS_FAMILY=$ID
        fi
    else
        error "Cannot determine the Linux distribution."
    fi

    # Run the appropriate installer
    case "$OS_FAMILY" in
        *debian*)
            install_on_debian
            ;;
        *rhel*|*fedora*|*centos*)
            install_on_rhel
            ;;
        *)
            error "Unsupported Linux distribution: $ID. This script supports Debian and Red Hat families."
            ;;
    esac

    configure_yara
    
    # Finalize the installation
    finalize_installation

    info "============================================================"
    info "✅ Wazuh Agent Installation and Registration Complete!"
    info "The agent is configured to report to manager: $WAZUH_MANAGER_IP"
    info "============================================================"
}

# Run the main function and log all output
main "$@" > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
