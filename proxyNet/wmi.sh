#!/bin/bash

# ============================================================================
# Universal Wazuh Installation Script
#
# This script automatically detects the Linux distribution and provides two
# installation options:
#
# 1.  All-in-One: Uses the Wazuh assisted installer to set up the manager,
#     indexer, and dashboard. This is the recommended and most reliable method
#     for a full stack deployment.
# 2.  Manager-Only: Uses the system's package manager to install only the
#     Wazuh manager component.
#
# It also includes a check to stop a running Splunk instance to prevent
# resource conflicts during the all-in-one installation.
# ============================================================================

# --- Globals and Utility Functions ---
LOG_FILE="/var/log/wazuh_universal_installer.log"
WazuhInstallationVersion="4.12"


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

# Function to check for and stop Splunk if it exists
handle_splunk_check() {
    info "Checking for an existing Splunk installation..."
    # Check if the Splunk directory exists
    if [ -d "/opt/splunk" ]; then
        info "Splunk installation found at /opt/splunk. To prevent resource conflicts, it can be temporarily stopped."
        read -p "Do you want to stop the Splunk service during this installation? (y/N): " -r STOP_SPLUNK
        STOP_SPLUNK=${STOP_SPLUNK:-n}

        if [[ "$STOP_SPLUNK" =~ ^[yY]([eE][sS])?$ ]]; then
            info "Stopping Splunk using the Splunk CLI..."
            # Check if the splunk binary is executable
            if [ -x "/opt/splunk/bin/splunk" ]; then
                /opt/splunk/bin/splunk stop
                check_success
                info "✔ OK: Splunk has been stopped."
            else
                error "Splunk binary not found or not executable at /opt/splunk/bin/splunk."
            fi
        else
            info "Skipping Splunk shutdown. Note: Resource conflicts may occur during installation."
        fi
    else
        info "Splunk directory /opt/splunk not found. No action needed."
    fi
}

# Function to install the Wazuh manager on Red Hat-based systems
install_manager_on_rhel() {
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
install_manager_on_debian() {
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

# Function to install the full Wazuh stack using the assisted installer
install_all_in_one_assisted() {
    info "--- Starting All-in-One Installation using Assisted Installer ---"
    handle_splunk_check

    info "Downloading the Wazuh installation assistant..."
    # Using the latest 4.x branch installer
    curl -sO curl -sO https://packages.wazuh.com/$WazuhInstallationVersion/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    check_success

    info "Running the All-in-One installation. This may take several minutes..."
    # The -a flag handles the full stack installation (indexer, manager, dashboard)
    bash wazuh-install.sh -a
    check_success

    # The assisted installer enables and starts all services automatically.
    info "✔ OK: Assisted installer has completed."
}


# Function to enable and start the Wazuh manager service (for manager-only installs)
finalize_manager_installation() {
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
    info "Starting Wazuh Universal Installer..."

    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root."
    fi
    
    # Ask user about the installation type
    read -p "Do you want to perform an All-in-One installation (Manager, Indexer, Dashboard)? (y/N): " -r INSTALL_AIO
    INSTALL_AIO=${INSTALL_AIO:-n} # Default to No

    if [[ "$INSTALL_AIO" =~ ^[yY]([eE][sS])?$ ]]; then
        # --- All-in-One Path ---
        install_all_in_one_assisted
    else
        # --- Manager-Only Path ---
        info "Starting Wazuh Manager-only installation."
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
                install_manager_on_debian
                ;;
            *rhel*|*fedora*|*centos*)
                install_manager_on_rhel
                ;;
            *)
                error "Unsupported Linux distribution: $ID. This script supports Debian and Red Hat families."
                ;;
        esac

        # Finalize the manager-only installation
        finalize_manager_installation
    fi

    # Install the additional ruleset after either installation path
    install_socfortress_rules

    # --- Final Summary ---
    if [[ "$INSTALL_AIO" =~ ^[yY]([eE][sS])?$ ]]; then
        FINAL_MESSAGE="✅ Wazuh All-in-One and SOCFortress Rules Installation Complete!"
        info "============================================================"
        info "$FINAL_MESSAGE"
        info "The Wazuh services are installed and running with the enhanced ruleset."
        info "Passwords for the installation have been saved to 'wazuh-passwords.txt'."
        info "You can access the Wazuh Dashboard at https://<your-server-ip>"
        info "============================================================"
    else
        FINAL_MESSAGE="✅ Wazuh Manager and SOCFortress Rules Installation Complete!"
        info "============================================================"
        info "$FINAL_MESSAGE"
        info "The Wazuh manager service is installed and running with the enhanced ruleset."
        info "============================================================"
    fi
}

# Run the main function and log all output
main "$@" > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
