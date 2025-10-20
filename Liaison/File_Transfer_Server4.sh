# ==============================================================================
# File: FileTransferServer4.sh
# Description: Installs/uninstalls and configures FTP (vsftpd), SFTP (via OpenSSH), or TFTP (tftpd-hpa/tftp-server) servers.
#              Prompts the user to select install or uninstall, then one service per run. Checks if the service is already installed/available;
#              if so, notifies and skips/exits as appropriate. If all services are installed at the start (for install mode), alerts and exits.
#              Supports Debian/Ubuntu (apt) and Fedora/CentOS (dnf) for compatibility with CCDC VMs as per Team Pack.
#              Services are started and enabled automatically on install; stopped and disabled on uninstall. Default configurations are used; team should harden
#              further (e.g., firewall rules via Palo Alto, user restrictions).
#              On install of FTP/SFTP, prompts for and creates credentials, saves them to /etc/fts_credentials.conf, and displays in view mode.
#
# Dependencies: None beyond standard package managers.
# Usage: sudo ./FileTransferServer4.sh
#        Follow on-screen prompts to select install/uninstall, then service.
# Notes: 
# - Run as root.
# - In CCDC, expose services via Palo Alto NAT if needed (e.g., to public IPs like 172.25.20+team#.x).
# - TFTP defaults to /srv/tftp or /var/lib/tftpboot; place files there.
# - SFTP uses SSH port 22; ensure no conflicts with existing SSH.
# - FTP on port 21; anonymous access disabled by default in vsftpd (but can be enabled with caution).
# - Credentials saved in /etc/fts_credentials.conf (securely); use in client script.
# ==============================================================================

#!/bin/bash

set -euo pipefail

# ------------------------------------------------------------------------------
# TeamPack Compliance Notice
# Server installation scripts must be run only in authorized lab/team environments.
# Running server installers on networks or systems you do not control may violate
# competition rules and acceptable use policies. Confirm you are authorized.
# ------------------------------------------------------------------------------
teampack_confirm() {
    echo ""
    echo "IMPORTANT: This script configures server services. Only run on authorized team/lab systems."
    read -p "I confirm I will only run this on my team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}

# Run TeamPack confirmation
teampack_confirm

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
/====================================================================\
||___________.__ .__                                                ||
||\_   _____/|__||  |    ____                                       ||
|| |    __)  |  ||  |  _/ __ \                                      ||
|| |     \   |  ||  |__\  ___/                                      ||
|| \___  /   |__||____/ \___  >                                     ||
||     \/                   \/                                      ||
||                                                                  ||
||___________                                  _____                ||
||\__    ___/_______ _____     ____    _______/ ____\ ____ _______  ||
||  |    |   \_  __ \\__  \   /    \  /  ___/\   __\_/ __ \\_  __ \ ||
||  |    |    |  | \/ / __ \_|   |  \ \___ \  |  |  \  ___/ |  | \/ ||
||  |____|    |__|   (____  /|___|  //____  > |__|   \___  >|__|    ||
||                        \/      \/      \/             \/         ||
\====================================================================/  
EOF
echo -e "\033[0m"
echo "File Transfer Server Installer/Uninstaller - For CCDC Team Prep"
echo "-------------------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
CRED_FILE="/etc/fts_credentials.conf"
LAST_CREATED_USERNAME=""
LAST_CREATED_PASSWORD=""
NOLOGIN_SHELL=""

detect_nologin_shell() {
    NOLOGIN_SHELL=$(command -v nologin 2>/dev/null || true)
    if [ -z "$NOLOGIN_SHELL" ]; then
        if [ -x /usr/sbin/nologin ]; then
            NOLOGIN_SHELL=/usr/sbin/nologin
        elif [ -x /sbin/nologin ]; then
            NOLOGIN_SHELL=/sbin/nologin
        else
            NOLOGIN_SHELL=/bin/false
        fi
    fi
}

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function for progress
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "%c " "${spinstr:0:1}"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b"
    done
    printf " \b"
}

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
            cat > /etc/vsftpd.conf << 'EOF'
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Get Local IP Address ---
get_local_ip() {
    local ip=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
    if [ -z "$ip" ]; then
        ip=$(hostname -I | awk '{print $1}')
    fi
    echo "$ip"
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
            user_sub_token=\$USER
            local_root=/srv/ftp/\$USER
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

# --- Get Credentials (for view mode) ---
get_credentials() {
    local service=$1
    local upper_service=$(echo "$service" | tr '[:lower:]' '[:upper:]')
    if [ -f "$CRED_FILE" ]; then
        local creds=$(grep "^\[$upper_service\]" "$CRED_FILE" | cut -d' ' -f2)
        if [ -n "$creds" ]; then
            echo "$creds"
            return 0
        fi
    fi
    echo "No credentials found."
}

# --- Save Credentials ---
save_credentials() {
    local service=$1
    local username=$2
    local password=$3
    local upper_service=$(echo "$service" | tr '[:lower:]' '[:upper:]')

    # Ensure file exists and is secure
    touch "$CRED_FILE"
    chmod 600 "$CRED_FILE"

    # Remove old entry if exists
    grep -v "^\[$upper_service\]" "$CRED_FILE" > "${CRED_FILE}.tmp" 2>/dev/null || true

    # Add new entry
    echo "[$upper_service] $username:$password" >> "${CRED_FILE}.tmp"
    mv "${CRED_FILE}.tmp" "$CRED_FILE"

    log_info "Credentials saved to $CRED_FILE for $service."
}

# --- Create Credentials for Service ---
create_credentials() {
    local service=$1
    local username=""
    local password=""

    log_info "Creating credentials for $service (required for connections)..."
    read -p "Enter username for $service: " username
    while [ -z "$username" ]; do
        log_warn "Username cannot be empty."
        read -p "Enter username for $service: " username
    done

    read -s -p "Enter password for $service: " password
    echo ""
    while [ -z "$password" ]; do
        log_warn "Password cannot be empty."
        read -s -p "Enter password for $service: " password
        echo ""
    done

    LAST_CREATED_USERNAME="$username"
    LAST_CREATED_PASSWORD="$password"
}

# --- Install FTP ---
install_ftp() {
    if is_ftp_installed; then
        log_warn "FTP (vsftpd) is already installed. Skipping."
        return 1
    fi

    log_info "Installing FTP (vsftpd)..."
    $UPDATE_CMD >/dev/null 2>&1

    create_credentials "FTP"
    local username="$LAST_CREATED_USERNAME"
    local password="$LAST_CREATED_PASSWORD"

    userdel -r "$username" 2>/dev/null || true
    mkdir -p /srv/ftp
    chown root:root /srv/ftp
    chmod 755 /srv/ftp
    useradd -d "/srv/ftp/$username" -s "$NOLOGIN_SHELL" -M "$username"
    echo "$username:$password" | chpasswd
    if ! passwd --status "$username" | grep -q "P"; then
        log_error "Failed to set password for user $username."
    fi
    mkdir -p "/srv/ftp/$username"
    chown "$username:$username" "/srv/ftp/$username"
    chmod 750 "/srv/ftp/$username"
    save_credentials "FTP" "$username" "$password"
    $INSTALL_CMD vsftpd >/dev/null 2>&1 &
    spinner $!

    # Basic config: disable anonymous, local users only
    cat > /etc/vsftpd.conf << 'EOF'
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chown_uploads=YES
chown_upload_mode=0664
xferlog_file=/var/log/vsftpd.log
secure_email_list_enable=NO
rsync_max_conn=5
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
allow_email_from=NO
chroot_local_user=YES
allow_writeable_chroot=YES
chroot_list_enable=NO
chroot_list_file=/etc/vsftpd.chroot_list
user_sub_token=$USER
local_root=/srv/ftp/$USER
EOF

    systemctl enable --now vsftpd >/dev/null 2>&1
    log_info "FTP installed and configured."
    return 0
}

# --- Install SFTP ---
install_sftp() {
    if is_sftp_installed; then
        log_warn "SFTP (openssh-server) is already installed. Skipping."
        return 1
    fi

    log_info "Installing SFTP (openssh-server)..."
    $UPDATE_CMD >/dev/null 2>&1
    $INSTALL_CMD openssh-server >/dev/null 2>&1 &
    spinner $!

    create_credentials "SFTP"
    local username="$LAST_CREATED_USERNAME"
    local password="$LAST_CREATED_PASSWORD"

    userdel -r "$username" 2>/dev/null || true
    useradd -m -s "$NOLOGIN_SHELL" "$username"
    echo "$username:$password" | chpasswd
    if ! passwd --status "$username" | grep -q "P"; then
        log_error "Failed to set password for user $username."
    fi
    save_credentials "SFTP" "$username" "$password"

    local home_dir="/home/$username"
    mkdir -p "$home_dir/upload"
    chown root:root "$home_dir"
    chmod 755 "$home_dir"
    chown "$username:$username" "$home_dir/upload"
    chmod 750 "$home_dir/upload"

    if ! getent group sftpusers >/dev/null; then
        groupadd sftpusers
    fi
    usermod -aG sftpusers "$username"

    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

    if grep -q '^#*Subsystem\s\+sftp' /etc/ssh/sshd_config; then
        sed -i 's/^#\?Subsystem\s\+sftp.*/Subsystem sftp \/usr\/lib\/openssh\/sftp-server/' /etc/ssh/sshd_config
    else
        echo "Subsystem sftp /usr/lib/openssh/sftp-server" >> /etc/ssh/sshd_config
    fi

    if ! grep -q '^Match Group sftpusers' /etc/ssh/sshd_config; then
cat << 'EOF' >> /etc/ssh/sshd_config

Match Group sftpusers
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
EOF
    fi

    systemctl restart ssh
    systemctl enable --now ssh >/dev/null 2>&1
    log_info "SFTP installed and configured for group sftpusers."
    return 0
}

# --- Install TFTP ---
install_tftp() {
    if is_tftp_installed; then
        log_warn "TFTP is already installed. Skipping."
        return 1
    fi

    log_info "Installing TFTP..."
    $UPDATE_CMD >/dev/null 2>&1
    if [ "$PKG_MANAGER" = "apt" ]; then
        $INSTALL_CMD tftpd-hpa >/dev/null 2>&1 &
        spinner $!
        # Config
        cat > /etc/default/tftpd-hpa << EOF
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/srv/tftp"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure"
EOF
        mkdir -p /srv/tftp
        systemctl enable --now tftpd-hpa >/dev/null 2>&1
    else
        $INSTALL_CMD tftp-server >/dev/null 2>&1 &
        spinner $!
        mkdir -p /var/lib/tftpboot
        systemctl enable --now tftp >/dev/null 2>&1
    fi
    log_info "TFTP installed and configured."
    return 0
}

# --- Uninstall FTP ---
uninstall_ftp() {
    if ! is_ftp_installed; then
        log_warn "FTP (vsftpd) is not installed. Skipping."
        return 1
    fi

    log_info "Uninstalling FTP (vsftpd)..."
    systemctl disable --now vsftpd >/dev/null 2>&1
    $REMOVE_CMD vsftpd >/dev/null 2>&1 &
    spinner $!

    # Delete user if credentials exist
    if [ -f "$CRED_FILE" ]; then
        local creds=$(get_credentials "FTP")
        if [ -n "$creds" ] && [ "$creds" != "No credentials found." ]; then
            local username=$(echo "$creds" | cut -d':' -f1)
            userdel -r "$username" 2>/dev/null || true
            log_info "Deleted user $username for clean uninstall."
        fi
    fi

    # Remove cred entry
    if [ -f "$CRED_FILE" ]; then
        local upper_service="FTP"
        grep -v "^\[$upper_service\]" "$CRED_FILE" > "${CRED_FILE}.tmp" 2>/dev/null || true
        mv "${CRED_FILE}.tmp" "$CRED_FILE"
    fi

    log_info "FTP uninstalled."
    return 0
}

# --- Uninstall SFTP ---
uninstall_sftp() {
    if ! is_sftp_installed; then
        log_warn "SFTP (openssh-server) is not installed. Skipping."
        return 1
    fi

    log_info "Uninstalling SFTP (openssh-server)..."
    systemctl disable --now ssh >/dev/null 2>&1
    $REMOVE_CMD openssh-server >/dev/null 2>&1 &
    spinner $!

    # Delete user if credentials exist
    if [ -f "$CRED_FILE" ]; then
        local creds=$(get_credentials "SFTP")
        if [ -n "$creds" ] && [ "$creds" != "No credentials found." ]; then
            local username=$(echo "$creds" | cut -d':' -f1)
            userdel -r "$username" 2>/dev/null || true
            log_info "Deleted user $username for clean uninstall."
        fi
    fi

    # Remove cred entry
    if [ -f "$CRED_FILE" ]; then
        local upper_service="SFTP"
        grep -v "^\[$upper_service\]" "$CRED_FILE" > "${CRED_FILE}.tmp" 2>/dev/null || true
        mv "${CRED_FILE}.tmp" "$CRED_FILE"
    fi

    log_info "SFTP uninstalled."
    return 0
}

# --- Uninstall TFTP ---
uninstall_tftp() {
    if ! is_tftp_installed; then
        log_warn "TFTP is not installed. Skipping."
        return 1
    fi

    log_info "Uninstalling TFTP..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        systemctl disable --now tftpd-hpa >/dev/null 2>&1
        $REMOVE_CMD tftpd-hpa >/dev/null 2>&1 &
    else
        systemctl disable --now tftp >/dev/null 2>&1
        $REMOVE_CMD tftp-server >/dev/null 2>&1 &
    fi
    spinner $!

    log_info "TFTP uninstalled."
    return 0
}

# --- Prompt for Install/Uninstall ---
prompt_mode() {
    log_info "Select mode:"
    echo "1) Install a service"
    echo "2) Uninstall a service"
    echo "3) View installed services information"
    read -p "Enter your choice (1-3): " mode
    case "$mode" in
        1) install_mode ;;
        2) uninstall_mode ;;
        3) view_mode ;;
        *) log_error "Invalid choice. Please select 1, 2, or 3." ;;
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

# --- View Mode ---
view_mode() {
    local ftp_installed=$(is_ftp_installed && echo "Yes" || echo "No")
    local sftp_installed=$(is_sftp_installed && echo "Yes" || echo "No")
    local tftp_installed=$(is_tftp_installed && echo "Yes" || echo "No")
    
    log_info "Installed services:"
    echo "1) FTP: $ftp_installed"
    echo "2) SFTP: $sftp_installed"
    echo "3) TFTP: $tftp_installed"
    
    if ! is_ftp_installed && ! is_sftp_installed && ! is_tftp_installed; then
        log_warn "No services are installed."
        return
    fi
    
    echo ""
    read -p "Select a service to view details (1-3): " choice
    
    local service=""
    case "$choice" in
        1) if is_ftp_installed; then service="FTP"; else log_warn "FTP not installed."; return; fi ;;
        2) if is_sftp_installed; then service="SFTP"; else log_warn "SFTP not installed."; return; fi ;;
        3) if is_tftp_installed; then service="TFTP"; else log_warn "TFTP not installed."; return; fi ;;
        *) log_error "Invalid choice. Please select 1, 2, or 3." ;;
    esac
    
    local ip=$(get_local_ip)
    
    log_info "Networking Information for $service:"
    echo "  - Server IP: $ip"
    case "$service" in
        FTP)
            echo "  - Port: 21"
            echo "  - Protocol: FTP"
            echo "  - Directory: /srv/ftp (default)"
            ;;
        SFTP)
            echo "  - Port: 22"
            echo "  - Protocol: SFTP (over SSH)"
            echo "  - Directory: User's home directory"
            ;;
        TFTP)
            if [ "$PKG_MANAGER" = "apt" ]; then
                echo "  - Port: 69 (UDP)"
                echo "  - Protocol: TFTP"
                echo "  - Directory: /srv/tftp"
            else
                echo "  - Port: 69 (UDP)"
                echo "  - Protocol: TFTP"
                echo "  - Directory: /var/lib/tftpboot"
            fi
            echo "  - Credentials: None (TFTP unauthenticated)"
            ;;
    esac

    if [ "$service" != "TFTP" ]; then
        local creds=$(get_credentials "$service")
        echo "  - Credentials: $creds (username:password)"
        if [ "$creds" = "No credentials found." ]; then
            log_warn "No credentials set. Run install again or create manually."
        fi
    fi
    echo ""

    # Export option
    read -p "Export credentials as base64 for client? (y/n): " export_creds
    if [[ $export_creds =~ ^[Yy]$ ]]; then
        if [ -f "$CRED_FILE" ] && [ "$service" != "TFTP" ]; then
            echo "Base64 encoded credentials:"
            base64 "$CRED_FILE" | tr -d '\n'
            echo ""
            log_info "Copy the above base64 string and decode on client: echo '<base64>' | base64 -d > /etc/fts_credentials.conf"
        else
            log_warn "No credentials file or TFTP (no creds)."
        fi
    fi

    log_info "Use this information in file_transfer_client.sh to connect."
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
        log_warn "Selected service could not be ${action}ed (e.g., already in state for some services)."
    fi
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    detect_nologin_shell
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "Remember to configure firewall rules (e.g., via Palo Alto) and harden services for CCDC security."
}

main "$@"