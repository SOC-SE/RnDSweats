# ==============================================================================
# File: Liaison/FileTransferServer.sh
# Description: Installs/uninstalls and configures FTP (vsftpd), SFTP (via OpenSSH), or TFTP (tftpd-hpa/tftp-server) servers.
#              Prompts the user to select install or uninstall, then one service per run. Checks if the service is already installed/available;
#              if so, notifies and skips/exits as appropriate. If all services are installed at the start (for install mode), alerts and exits.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS (dnf) for compatibility with CCDC VMs as per Team Pack.
#              Services are started and enabled automatically on install; stopped and disabled on uninstall. Default configurations are used; team should harden
#              further (e.g., firewall rules via Palo Alto, user restrictions).
#
# Dependencies: None beyond standard package managers.
# Usage: sudo ./FileTransferServer.sh
#        Follow on-screen prompts to select install/uninstall, then service.
# Notes: 
# - Run as root.
# - In CCDC, expose services via Palo Alto NAT if needed (e.g., to public IPs like 172.25.20+team#.x).
# - TFTP defaults to /srv/tftp or /var/lib/tftpboot; place files there.
# - SFTP uses SSH port 22; ensure no conflicts with existing SSH.
# - FTP on port 21; anonymous access disabled by default in vsftpd (but can be enabled with caution).
# ==============================================================================

#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
   _____ _ _     _____                     _____           _             
  |   __|_| |___|   __|___ ___ _ _ ___   |   __|_____ ___| |_ ___ ___   
  |   __| | | -_|_   _|  _|  _| | | -_|  |__   |     | . |  _|  _| -_|  
  |__|  |_|_|___|__|  |___|___|___|___|  |_____|_|_|_|  _|_| |_| |___|  
                                              |_|                        
EOF
echo -e "\033[0m"
echo "File Transfer Server Installer/Uninstaller - For CCDC Team Prep"
echo "-------------------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
        QUERY_CMD="dpkg -s"
        REMOVE_CMD="apt-get purge -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
        QUERY_CMD="rpm -q"
        REMOVE_CMD="dnf remove -y"
    else
        log_error "Unsupported package manager. Only apt (Debian/Ubuntu) and dnf (Fedora/CentOS) are supported."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Check if Service Installed ---
is_ftp_installed() {
    if [ "$PKG_MANAGER" = "apt" ]; then
        $QUERY_CMD vsftpd &> /dev/null
    else
        $QUERY_CMD vsftpd &> /dev/null
    fi
}

is_sftp_installed() {
    if [ "$PKG_MANAGER" = "apt" ]; then
        $QUERY_CMD openssh-server &> /dev/null
    else
        $QUERY_CMD openssh-server &> /dev/null
    fi
}

is_tftp_installed() {
    if [ "$PKG_MANAGER" = "apt" ]; then
        $QUERY_CMD tftpd-hpa &> /dev/null
    else
        $QUERY_CMD tftp-server &> /dev/null
    fi
}

# --- Check if All Installed ---
all_installed() {
    is_ftp_installed && is_sftp_installed && is_tftp_installed
}

# --- Install Functions ---
install_ftp() {
    if is_ftp_installed; then
        log_warn "FTP (vsftpd) is already installed."
        return 1
    fi
    log_info "Installing FTP (vsftpd)..."
    $UPDATE_CMD
    $INSTALL_CMD vsftpd
    systemctl enable vsftpd
    systemctl start vsftpd
    log_info "FTP installed and started on port 21. Configure /etc/vsftpd.conf for security (e.g., disable anonymous)."
    print_connection_instructions "FTP"
    return 0
}

install_sftp() {
    if is_sftp_installed; then
        log_warn "SFTP (OpenSSH) is already installed."
        return 1
    fi
    log_info "Installing SFTP (via OpenSSH-server)..."
    $UPDATE_CMD
    $INSTALL_CMD openssh-server
    # Ensure SFTP subsystem is enabled
    grep -q '^Subsystem sftp' /etc/ssh/sshd_config || echo 'Subsystem sftp /usr/lib/openssh/sftp-server' >> /etc/ssh/sshd_config
    systemctl enable ssh
    systemctl restart ssh
    log_info "SFTP installed and started on port 22. Configure /etc/ssh/sshd_config for chroot or user restrictions."
    print_connection_instructions "SFTP"
    return 0
}

install_tftp() {
    if is_tftp_installed; then
        log_warn "TFTP is already installed."
        return 1
    fi
    log_info "Installing TFTP..."
    $UPDATE_CMD
    if [ "$PKG_MANAGER" = "apt" ]; then
        $INSTALL_CMD tftpd-hpa
        # Default config: /etc/default/tftpd-hpa
        sed -i 's|^TFTP_DIRECTORY=.*|TFTP_DIRECTORY="/srv/tftp"|' /etc/default/tftpd-hpa
        mkdir -p /srv/tftp
        chown -R nobody:nogroup /srv/tftp
        systemctl enable tftpd-hpa
        systemctl restart tftpd-hpa
    else
        $INSTALL_CMD tftp-server
        # Default dir: /var/lib/tftpboot
        mkdir -p /var/lib/tftpboot
        chown -R nobody:nobody /var/lib/tftpboot
        systemctl enable in.tftpd
        systemctl restart in.tftpd
    fi
    log_info "TFTP installed and started on UDP port 69. Directory: /srv/tftp (apt) or /var/lib/tftpboot (dnf)."
    print_connection_instructions "TFTP"
    return 0
}

# --- Uninstall Functions ---
uninstall_ftp() {
    if ! is_ftp_installed; then
        log_warn "FTP (vsftpd) is not installed."
        return 1
    fi
    log_info "Uninstalling FTP (vsftpd)..."
    systemctl stop vsftpd || true
    systemctl disable vsftpd || true
    $REMOVE_CMD vsftpd
    log_info "FTP uninstalled."
    return 0
}

uninstall_sftp() {
    if ! is_sftp_installed; then
        log_warn "SFTP (OpenSSH) is not installed."
        return 1
    fi
    log_info "Uninstalling SFTP (via OpenSSH-server)..."
    systemctl stop ssh || true
    systemctl disable ssh || true
    $REMOVE_CMD openssh-server
    log_info "SFTP uninstalled."
    return 0
}

uninstall_tftp() {
    if ! is_tftp_installed; then
        log_warn "TFTP is not installed."
        return 1
    fi
    log_info "Uninstalling TFTP..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        systemctl stop tftpd-hpa || true
        systemctl disable tftpd-hpa || true
        $REMOVE_CMD tftpd-hpa
    else
        systemctl stop in.tftpd || true
        systemctl disable in.tftpd || true
        $REMOVE_CMD tftp-server
    fi
    log_info "TFTP uninstalled."
    return 0
}

# --- Print Connection Instructions ---
print_connection_instructions() {
    local service=$1
    log_info "Connection Instructions for $service (to enable file transfers from other machines/VMs):"
    echo "  - Ensure the service is exposed via Palo Alto NAT (e.g., public IP: 172.25.20+team#.x) as per Team Pack."
    echo "  - From another machine (e.g., client VM), use these commands:"
    if [ "$service" = "FTP" ]; then
        echo "    - Install ftp client if needed: sudo apt install ftp (or dnf install ftp)"
        echo "    - Connect: ftp <server_ip> (port 21). Login with a valid user (e.g., anonymous if enabled, but disable for security)."
        echo "    - Commands: ls (list), get <file> (download), put <file> (upload), bye (exit)."
        echo "    - Security Note: Use strong passwords; edit /etc/vsftpd.conf to restrict users."
    elif [ "$service" = "SFTP" ]; then
        echo "    - Install sftp client if needed: sudo apt install openssh-client (or dnf install openssh-clients)"
        echo "    - Connect: sftp <user>@<server_ip> (port 22)."
        echo "    - Commands: ls (list), get <file> (download), put <file> (upload), exit."
        echo "    - Security Note: Use SSH keys for auth; chroot users in /etc/ssh/sshd_config."
    elif [ "$service" = "TFTP" ]; then
        echo "    - Install tftp client if needed: sudo apt install tftp (or dnf install tftp)"
        echo "    - Connect: tftp <server_ip> (UDP port 69)."
        echo "    - Commands: get <file> (download), put <file> (upload), quit."
        echo "    - Files go to/from the TFTP dir (/srv/tftp or /var/lib/tftpboot). No auth by default – harden with firewall rules."
    fi
    echo "  - Test locally first: e.g., curl -v ftp://localhost/ for FTP."
    echo "  - For inter-VM transfers in CCDC: Ensure firewall allows traffic; use internal IPs if not NAT'd."
    log_warn "Harden immediately: Restrict access, monitor logs, and avoid exposing to untrusted networks."
}

# --- Prompt for Install/Uninstall ---
prompt_mode() {
    log_info "Select mode:"
    echo "1) Install a service"
    echo "2) Uninstall a service"
    read -p "Enter your choice (1-2): " mode
    case "$mode" in
        1) install_mode ;;
        2) uninstall_mode ;;
        *) log_error "Invalid choice. Please select 1 or 2." ;;
    esac
}

# --- Install Mode ---
install_mode() {
    if all_installed; then
        log_warn "All services (FTP, SFTP, TFTP) are already installed. No action needed."
        exit 0
    fi
    prompt_choice install
}

# --- Uninstall Mode ---
uninstall_mode() {
    local ftp_installed=$(is_ftp_installed && echo "Yes" || echo "No")
    local sftp_installed=$(is_sftp_installed && echo "Yes" || echo "No")
    local tftp_installed=$(is_tftp_installed && echo "Yes" || echo "No")
    
    log_info "Installed services:"
    echo "FTP: $ftp_installed"
    echo "SFTP: $sftp_installed"
    echo "TFTP: $tftp_installed"
    
    if ! is_ftp_installed && ! is_sftp_installed && ! is_tftp_installed; then
        log_warn "No services are installed. Nothing to uninstall."
        exit 0
    fi
    prompt_choice uninstall
}

# --- Prompt User for Service Choice (Install or Uninstall) ---
prompt_choice() {
    local action=$1  # install or uninstall
    local services=( "FTP" "SFTP" "TFTP" )
    local func_prefix=""
    if [ "$action" = "uninstall" ]; then
        func_prefix="un"
    fi
    
    log_info "Select a service to $action:"
    echo "1) FTP"
    echo "2) SFTP"
    echo "3) TFTP"
    read -p "Enter your choice (1-3): " choice
    
    local service=""
    case "$choice" in
        1) service="FTP" ;;
        2) service="SFTP" ;;
        3) service="TFTP" ;;
        *) log_error "Invalid choice. Please select 1, 2, or 3." ;;
    esac
    
    read -p "Are you sure you want to $action $service? (y/n): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_warn "Action cancelled."
        exit 0
    fi
    
    local func="${func_prefix}install_${service,,}"
    $func
    if [ $? -eq 0 ]; then
        log_info "Service ${action}ed successfully."
    else
        log_warn "Selected service could not be ${action}ed (e.g., already/not in state)."
    fi
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "Remember to configure firewall rules (e.g., via Palo Alto) and harden services for CCDC security."
}

main "$@"