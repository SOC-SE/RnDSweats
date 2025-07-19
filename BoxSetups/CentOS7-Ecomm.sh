#!/bin/bash
# ==============================================================================
# CentOS-Install.sh
#
# Author: Linux System Administration Expert
# Date: 2025-08-15
# Description: Automates the installation of PrestaShop 1.6.1.23 on a
#              CentOS 7 server for competitions.
#
# This script performs the following actions:
# 1. Checks for root privileges.
# 2. Fixes CentOS 7 EOL repositories.
# 3. Installs a LAMP stack (Apache, MariaDB, PHP 7.1).
# 4. Creates a database and user for PrestaShop.
# 5. Downloads and installs PrestaShop 1.6.1.23 via CLI.
# 6. Sets appropriate permissions in two stages (pre- and post-install).
# 7. Cleans up installation files and reports the admin URL.
#
# WARNING: This script creates an intentionally insecure environment for
#          educational and competitive purposes. It does NOT run
#          mysql_secure_installation and uses predictable credentials.
#          DO NOT USE IN A PRODUCTION ENVIRONMENT.
# ==============================================================================

# --- Script Configuration ---
set -e
set -u
set -o pipefail

# --- Variables ---
DB_NAME="prestashop_db"
DB_USER="ps_user"
DB_PASS="Changeme1!"
ADMIN_EMAIL="sysadmin@comp.local"
ADMIN_PASS="Changeme1!"
PRESTASHOP_VERSION="1.6.1.23"
PRESTASHOP_URL="https://github.com/PrestaShop/PrestaShop/releases/download/1.7.4.4/prestashop_1.7.4.4.zip"
PRESTASHOP_ZIP="prestashop.zip"
INSTALL_DIR="/var/www/html"
SHOP_DIR="${INSTALL_DIR}/prestashop"
SERVER_IP=$(hostname -I | awk '{print $1}')
APACHE_USER="apache" # Use 'www-data' on Debian/Ubuntu

# --- Helper Functions ---
log_info() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2
    exit 1
}

# --- Main Logic ---

# 1. Prerequisite Check
if [ -d "${SHOP_DIR}" ]; then
    log_error "PrestaShop directory already exists. Aborting to prevent overwriting."
fi

log_info "Starting PrestaShop ${PRESTASHOP_VERSION} installation on CentOS 7..."

# 2. CentOS 7 EOL Repository Fix
if ! grep -q "vault.centos.org" /etc/yum.repos.d/CentOS-Base.repo; then
    log_info "CentOS 7 mirrors are not set to vault. Correcting..."
    cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Base.repo
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-Base.repo
    log_info "Cleaning YUM cache and rebuilding..."
    yum clean all
    yum makecache
else
    log_info "CentOS 7 vault mirrors are already configured."
fi

# 3. Install LAMP Stack
log_info "Installing Apache, MariaDB, and utilities..."
yum install -y httpd mariadb-server wget unzip

log_info "Starting and enabling services..."
systemctl start httpd && systemctl enable httpd
systemctl start mariadb && systemctl enable mariadb

log_info "Configuring firewall..."
firewall-cmd --permanent --add-service=http --add-service=https
firewall-cmd --reload

# 4. Install PHP 7.1
log_info "Installing PHP 7.1 repositories..."
yum install -y epel-release yum-utils
yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum-config-manager --enable remi-php71

log_info "Installing PHP 7.1 and extensions..."
yum install -y php php-cli php-fpm php-mysqlnd php-zip php-devel php-gd php-mcrypt \
               php-mbstring php-curl php-xml php-pear php-bcmath php-json php-intl php-opcache

log_info "Restarting Apache..."
systemctl restart httpd

# 5. Database and Application Provisioning
log_info "Creating MariaDB database and user..."
mysql -u root <<-MYSQL_SCRIPT
CREATE DATABASE ${DB_NAME};
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT
log_info "Database and user created."

log_info "Downloading PrestaShop ${PRESTASHOP_VERSION}..."
wget -O "${INSTALL_DIR}/${PRESTASHOP_ZIP}" "${PRESTASHOP_URL}"

log_info "Extracting PrestaShop files..."
unzip -o "${INSTALL_DIR}/${PRESTASHOP_ZIP}" -d "${INSTALL_DIR}"
unzip -o "${INSTALL_DIR}/prestashop.zip" -d "${INSTALL_DIR}"

# 6. Set Pre-Installation Permissions (Stage 1)
log_info "Setting pre-installation permissions (Stage 1)..."
chown -R "${APACHE_USER}:${APACHE_USER}" "${SHOP_DIR}"
find "${SHOP_DIR}" -type d -exec chmod 755 {} \;
find "${SHOP_DIR}" -type f -exec chmod 644 {} \;

# Grant specific write permissions needed by the installer
chmod -R u+w "${SHOP_DIR}/config"
chmod -R u+w "${SHOP_DIR}/cache"
chmod -R u+w "${SHOP_DIR}/log"
chmod -R u+w "${SHOP_DIR}/img"
chmod -R u+w "${SHOP_DIR}/mails"
chmod -R u+w "${SHOP_DIR}/modules"
chmod -R u+w "${SHOP_DIR}/themes/default-bootstrap/cache"
chmod -R u+w "${SHOP_DIR}/translations"
chmod -R u+w "${SHOP_DIR}/upload"
chmod -R u+w "${SHOP_DIR}/download"

# 7. Run PrestaShop CLI Installer
log_info "Running PrestaShop command-line installer..."
if [ -f "${SHOP_DIR}/install/index_cli.php" ]; then
    php "${SHOP_DIR}/install/index_cli.php" --domain="${SERVER_IP}" \
    --db_server=127.0.0.1 --db_name="${DB_NAME}" --db_user="${DB_USER}" \
    --db_password="${DB_PASS}" --prefix=ps_ --name="CCDC Store" \
    --email="${ADMIN_EMAIL}" --password="${ADMIN_PASS}" --language=en
else
    log_error "PrestaShop installation script not found. Aborting."
fi

# 8. Post-Installation Cleanup
log_info "Cleaning up installation files..."
rm -rf "${SHOP_DIR}/install"
rm -f "${INSTALL_DIR}/${PRESTASHOP_ZIP}"
rm -f "${INSTALL_DIR}/prestashop.zip"
rm -f "${INSTALL_DIR}/Install_PrestaShop.html"

# 9. Set Post-Installation Permissions (Stage 2 - Hardening)
log_info "Setting final, hardened permissions (Stage 2)..."
# Reset all directories to 755 and files to 644
find "${SHOP_DIR}" -type d -exec chmod 755 {} \;
find "${SHOP_DIR}" -type f -exec chmod 644 {} \;
# Lock down the config directory - make it read-only
chmod -R 555 "${SHOP_DIR}/config/"
# But the theme cache still needs to be writable
chmod -R 755 "${SHOP_DIR}/themes/default-bootstrap/cache/"
log_info "Permissions have been hardened."

# 10. Discover and Report Admin URL
log_info "Discovering the randomized admin directory..."
ADMIN_DIR_NAME=$(find "${SHOP_DIR}" -maxdepth 1 -type d -name "admin*" -printf "%f\n")
if [ -n "${ADMIN_DIR_NAME}" ]; then
    ADMIN_URL="http://${SERVER_IP}/prestashop/${ADMIN_DIR_NAME}"
    log_info "Installation Complete! ✅"
    echo "========================================================================"
    echo " PrestaShop Admin Panel:"
    echo " URL: ${ADMIN_URL}"
    echo " User: ${ADMIN_EMAIL}"
    echo " Password: ${ADMIN_PASS}"
    echo "========================================================================"
else
    log_error "Could not determine the admin directory URL."
fi

exit 0
