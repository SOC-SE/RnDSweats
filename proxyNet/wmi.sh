#!/bin/bash

# ============================================================================
# Universal Wazuh Manager Installation Script
#
# This script automatically detects the Linux distribution (Debian-based or
# Red Hat-based) and installs the Wazuh manager. It does not install the
# Wazuh indexer or Wazuh dashboard components. After installation, it will
# also download and install the SOCFortress community ruleset.
#
# Supported OS Families:
#   - Debian (e.g., Debian, Ubuntu)
#   - Red Hat (e.g., RHEL, CentOS, Oracle Linux, Fedora, Rocky Linux)
# ============================================================================

# --- Globals and Utility Functions ---
LOG_FILE="/var/log/wazuh_universal_installer.log"

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

# Function to install the Wazuh manager on Red Hat-based systems
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

    info "Installing the Wazuh manager package..."
    if command -v dnf &> /dev/null; then
        dnf install -y wazuh-manager
    else
        yum install -y wazuh-manager
    fi
    check_success
}

# Function to install the Wazuh manager on Debian-based systems
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

    info "Installing the Wazuh manager package..."
    apt-get update
    apt-get install -y wazuh-manager
    check_success
}

# Function to enable and start the Wazuh manager service
finalize_installation() {
    info "Enabling and starting the wazuh-manager service..."
    systemctl daemon-reload
    check_success
    systemctl enable wazuh-manager
    check_success
    systemctl start wazuh-manager
    check_success

    info "Waiting for the service to initialize..."
    sleep 15

    if systemctl is-active --quiet wazuh-manager; then
        info "✔ OK: The wazuh-manager service is active and running."
    else
        error "The wazuh-manager service failed to start. Check the logs with 'journalctl -u wazuh-manager'."
    fi
}

# Function to install the SOCFortress ruleset
install_socfortress_rules() {
    info "--- Starting SOCFortress Rules Installation ---"
    info "Downloading and running the SOCFortress rules installation script..."
    curl -so wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/wazuh-rules/main/wazuh_socfortress_rules.sh && bash wazuh_socfortress_rules.sh
    check_success
    info "✔ OK: SOCFortress ruleset installation script finished."
    info "The wazuh-manager service will have been restarted by the script."
}


# --- Main Execution ---
main() {
    # Start logging
    rm -f "$LOG_FILE"
    info "Starting Wazuh Manager Universal Installer..."

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

    # Finalize the base installation
    finalize_installation

    # Install the additional ruleset
    install_socfortress_rules

    info "============================================================"
    info "✅ Wazuh Manager and SOCFortress Rules Installation Complete!"
    info "The Wazuh manager is installed and running with the enhanced ruleset."
    info "============================================================"
}

# Run the main function and log all output
main "$@" > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
