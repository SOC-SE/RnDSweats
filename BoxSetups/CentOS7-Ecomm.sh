#!/bin/bash
set -x

# ==============================================================================
# CentOS-Install.sh
#
# Author: Linux System Administration Expert
# Date:   07/20/2025
#
# Description:
# This script automates the installation of PrestaShop 1.6.1.20 on a clean
# CentOS 7 system. It is designed for non-interactive execution.
#
# Key Operations:
# 1.  Validates root execution and sets up logging.
# 2.  Fixes CentOS 7 YUM repositories to point to the vault archives.
# 3.  Installs Apache (httpd), MariaDB, and PHP 7.1 with required extensions.
# 4.  Performs a non-interactive, secure installation of MariaDB.
# 5.  Downloads and installs PrestaShop 1.6.1.20 using the CLI installer.
# 6.  Sets appropriate file and directory permissions.
# 7.  Configures the system to an insecure baseline for cybersecurity exercises
#     by permanently disabling the firewall and setting SELinux to Permissive.
#
# Usage:
#     chmod +x CentOS-Install.sh
#     sudo ./CentOS-Install.sh
#
# ==============================================================================

# --- Script Configuration Block ---
# All user-configurable variables are defined here for easy modification.

# MariaDB/MySQL Credentials
DB_ROOT_PASS="Changeme1!"
DB_NAME="prestashop"
DB_USER="prestashop_user"
DB_PASS="Changeme1!" # As per user request, can be changed.

# PrestaShop Configuration
PS_VERSION="1.6.1.20"
PS_DOMAIN="ecomm.comp.local" # Use a valid FQDN or IP address
PS_STORE_NAME="Greg's Store"
PS_ADMIN_EMAIL="admin@comp.local"
PS_ADMIN_PASS="Changeme1!"
PS_COUNTRY_ISO="us" # ISO 3166-1 alpha-2 code for the store's country

# System Paths and URLs
WEB_ROOT="/var/www/html"
PS_INSTALL_DIR="${WEB_ROOT}/prestashop"
PS_DOWNLOAD_URL="https://download.prestashop.com/download/releases/prestashop_${PS_VERSION}.zip"
LOG_FILE="/var/log/prestashop_install.log"

# --- End Configuration Block ---


# --- Global Variable ---
# Declared globally to be accessible after being set in a function.
#ADMIN_DIR=""


# --- Function Definitions ---

# Function to log messages with a timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Function to check for root privileges
check_root() {
    if [ $EUID -ne 0 ]; then
#        log "ERROR: This script must be run as root."
        exit 1
    fi
}

# Function to fix CentOS 7 EOL repositories
fix_centos_repos() {
    log "Checking and fixing CentOS 7 repositories..."
    # Check if the domain needs to be changed to the vault archive.
    if grep -q "mirror.centos.org" /etc/yum.repos.d/CentOS-*.repo; then
        log "Standard mirrors found. Switching to vault.centos.org."
        
        # Comment out the mirrorlist line to enable the baseurl.
        sed -i 's/^mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
        
        # Uncomment the baseurl line. This is more robust than matching the full URL.
        sed -i 's/^#baseurl/baseurl/' /etc/yum.repos.d/CentOS-*.repo
        
        # Replace the domain with the vault server. This handles all repo files.
        sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/CentOS-*.repo
        
        log "Repositories successfully pointed to vault."
        yum clean all && yum makecache
        log "YUM cache cleaned and rebuilt."
    else
        log "Repositories appear to be already fixed or are non-standard. Skipping fix."
    fi
}
# Function to install required packages
install_dependencies() {
    log "Installing prerequisite packages and third-party repositories..."
    yum install -y epel-release wget unzip
    
    log "Installing Webtatic repository for PHP 7.1..."
    rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm

    log "Installing LAMP stack: Apache, MariaDB, and PHP 7.1..."
    yum install -y httpd mariadb-server \
                   php71w php71w-cli php71w-common php71w-gd php71w-mcrypt \
                   php71w-mysqlnd php71w-pdo php71w-xml php71w-mbstring \
                   php71w-curl php71w-zip php71w-intl php71w-soap \
                   php71w-bcmath php71w-json php71w-opcache
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to install one or more required packages."
        exit 1
    fi
    log "All dependencies installed successfully."
}

# Function to configure and secure MariaDB non-interactively
configure_mariadb() {
    log "Starting and enabling MariaDB service..."
    systemctl start mariadb
    systemctl enable mariadb

    log "Securing MariaDB installation non-interactively..."
    mysql -u root <<-EOF
UPDATE mysql.user SET Password = PASSWORD('${DB_ROOT_PASS}') WHERE User = 'root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to secure MariaDB."
        exit 1
    fi
    log "MariaDB secured."

    log "Creating PrestaShop database and user..."
    mysql -u root -p"${DB_ROOT_PASS}" <<-EOF
CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to create PrestaShop database or user."
        exit 1
    fi
    log "PrestaShop database and user created successfully."
}

# Function to configure Apache
configure_apache() {
    log "Starting and enabling Apache (httpd) service..."
    systemctl start httpd
    systemctl enable httpd

    log "Creating Apache VirtualHost for PrestaShop..."
    cat > /etc/httpd/conf.d/prestashop.conf <<-EOF
<VirtualHost *:80>
    ServerName ${PS_DOMAIN}
    DocumentRoot ${PS_INSTALL_DIR}
    
    <Directory ${PS_INSTALL_DIR}>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog /var/log/httpd/${PS_DOMAIN}-error.log
    CustomLog /var/log/httpd/${PS_DOMAIN}-access.log combined
</VirtualHost>
EOF
    log "VirtualHost created. Restarting Apache..."
    systemctl restart httpd
}

# Function to download and install PrestaShop
install_prestashop() {
    log "Downloading PrestaShop version ${PS_VERSION}..."
    wget -q -O /tmp/prestashop.zip "${PS_DOWNLOAD_URL}"
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to download PrestaShop."
        exit 1
    fi

    log "Extracting PrestaShop to ${WEB_ROOT}..."
    unzip -q /tmp/prestashop.zip -d "${WEB_ROOT}"
    
    if [ ! -d "${PS_INSTALL_DIR}" ]; then
        log "ERROR: PrestaShop installation directory not found at ${PS_INSTALL_DIR} after extraction."
        exit 1
    fi
    
    log "PrestaShop extracted. Running CLI installer..."
    cd "${PS_INSTALL_DIR}/install"
    
    php index_cli.php --domain="${PS_DOMAIN}" \
                      --db_server=127.0.0.1 \
                      --db_name="${DB_NAME}" \
                      --db_user="${DB_USER}" \
                      --db_password="${DB_PASS}" \
                      --prefix=ps_ \
                      --name="${PS_STORE_NAME}" \
                      --email="${PS_ADMIN_EMAIL}" \
                      --password="${PS_ADMIN_PASS}" \
                      --country="${PS_COUNTRY_ISO}" \
                      --newsletter=0 \
                      --send_email=0

    if [ $? -ne 0 ]; then
        log "ERROR: PrestaShop CLI installation failed."
        exit 1
    fi
    log "PrestaShop CLI installation completed successfully."
}

# Function to set permissions and perform cleanup
finalize_installation() {
    log "Setting file and directory permissions..."
    chown -R apache:apache "${PS_INSTALL_DIR}"
    find "${PS_INSTALL_DIR}" -type d -exec chmod 755 {} \;
    find "${PS_INSTALL_DIR}" -type f -exec chmod 644 {} \;
    log "Permissions set."

    log "Performing post-installation cleanup..."
    if [ -d "${PS_INSTALL_DIR}/install" ]; then
        rm -rf "${PS_INSTALL_DIR}/install"
        log "Installation directory removed."
    fi

    ADMIN_DIR=$(find "${PS_INSTALL_DIR}" -maxdepth 1 -type d -name "admin*" | xargs basename)
    
    if [ -n "${ADMIN_DIR}" ]; then
        log "IMPORTANT: Your admin directory has been renamed to: /${ADMIN_DIR}"
        echo "Admin URL: http://${PS_DOMAIN}/${ADMIN_DIR}" >> "${LOG_FILE}"
        echo "Admin User: ${PS_ADMIN_EMAIL}" >> "${LOG_FILE}"
        echo "Admin Pass: ${PS_ADMIN_PASS}" >> "${LOG_FILE}"
    else
        log "WARNING: Could not determine the new admin directory name."
    fi

    rm -f /tmp/prestashop.zip
    log "Cleanup complete."
}

# --- SCRIPT EDITED HERE ---
# Function to establish the insecure baseline for the competition
create_insecure_baseline() {
    log "WARNING: Establishing insecure baseline by permanently disabling all firewalls."

    log "Setting SELinux to Permissive mode..."
    setenforce 0
    sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
    log "SELinux is now in Permissive mode and will remain so on reboot."

    # Stop and disable firewalld (the default on CentOS 7) to prevent conflicts.
    log "Stopping and disabling firewalld service..."
    systemctl stop firewalld
    systemctl disable firewalld
    systemctl mask firewalld # 'mask' prevents it from being started by other services.

    # Ensure the iptables-services package is installed to manage the legacy service
    log "Ensuring iptables-services package is installed..."
    yum install -y iptables-services

    # Flush all rules and set the default policies to ACCEPT for the current session.
    # This ensures immediate open access.
    log "Flushing all current iptables rules and setting policies to ACCEPT..."
    iptables -F
    iptables -X
    iptables -Z
    iptables -t nat -F
    iptables -t nat -X
    iptables -t nat -Z
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t mangle -Z
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # CRITICAL: Save the now empty, "accept all" ruleset to the configuration file.
    # This overwrites the ruleset that gets loaded on reboot.
    log "Saving empty 'allow all' ruleset to /etc/sysconfig/iptables..."
    iptables-save > /etc/sysconfig/iptables

    # Stop and disable the iptables service. This is a final measure to prevent
    # it from starting at boot, even if another process were to enable it.
    log "Stopping and disabling the iptables service..."
    systemctl stop iptables
    systemctl disable iptables
    
    log "The firewall persistent rules have been flushed and deleted. All ports will remain open after reboot."
    log "Insecure baseline established."
}
# --- END EDIT ---

# --- Main Execution Logic ---

# Redirect all output to log file and console
exec > >(tee -a "$LOG_FILE") 2>&1

log "Starting PrestaShop ${PS_VERSION} installation on CentOS 7."

check_root
fix_centos_repos
install_dependencies
configure_mariadb
configure_apache
install_prestashop
finalize_installation
create_insecure_baseline

log "--- INSTALLATION SUMMARY ---"
log "PrestaShop URL: http://${PS_DOMAIN}/"
log "Admin URL:      http://${PS_DOMAIN}/${ADMIN_DIR}"
log "Admin User:     ${PS_ADMIN_EMAIL}"
log "Admin Pass:     ${PS_ADMIN_PASS}"
log "Database Name:  ${DB_NAME}"
log "Database User:  ${DB_USER}"
log "Database Pass:  ${DB_PASS}"
log "Full installation log is available at: ${LOG_FILE}"
log "--- SCRIPT FINISHED ---"

exit 0
