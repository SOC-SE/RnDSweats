#!/bin/bash

# ==============================================================================
# CentOS-Install.sh
#
# Description:
# This script automates the installation of PrestaShop 1.7.4.4 and its
# dependencies (Apache, MariaDB, PHP 7.2) on a CentOS 7 system.
# It is specifically designed for the MWCCDC competition environment,
# creating a standardized but intentionally insecure baseline.
#
# Author: Linux System Administration Expert
# Version: 1.1
# ==============================================================================

# --- Configuration Variables ---
PRESTASHOP_VERSION="1.7.4.4"
PRESTASHOP_URL="https://github.com/PrestaShop/PrestaShop/releases/download/${PRESTASHOP_VERSION}/prestashop_${PRESTASHOP_VERSION}.zip"
DB_NAME="prestashop_db"
DB_USER="ps_user"
DB_PASS="Changeme1!" # Intentionally weak password for competition purposes
WEB_ROOT="/var/www/html"
LOG_FILE="/var/log/prestashop_install.log"

# --- Helper Functions ---
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

check_root() {
    # Corrected: Added condition to check for root user
    if [ "$EUID" -ne 0 ]; then
        log "ERROR: This script must be run as root."
        exit 1
    fi
}

# --- Main Script Logic ---

# Step 0: Initial Setup
check_root
log "Starting PrestaShop ${PRESTASHOP_VERSION} installation on CentOS 7."
touch "$LOG_FILE"
chown root:root "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Step 1: Fix CentOS 7 EOL Repositories
log "Phase 1: System Preparation and Repository Correction"
if grep -q "mirror.centos.org" /etc/yum.repos.d/CentOS-Base.repo; then
    log "CentOS 7 repositories appear to be pointing to standard mirrors. Fixing for EOL..."
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo &>> "$LOG_FILE"
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo &>> "$LOG_FILE"
    log "Repositories updated to point to vault.centos.org."
    yum clean all &>> "$LOG_FILE"
    yum makecache &>> "$LOG_FILE"
    log "Yum cache rebuilt."
else
    log "Repositories already seem to be configured for vault or are custom. Skipping modification."
fi
yum -y update &>> "$LOG_FILE"
log "System packages updated."

# Step 2: Install LAMP Stack (Apache & MariaDB)
log "Phase 2: LAMP Stack Installation"
log "Installing Apache (httpd) and MariaDB..."
yum install -y httpd mariadb-server wget unzip &>> "$LOG_FILE"
if [ $? -ne 0 ]; then
    log "ERROR: Failed to install httpd or mariadb-server. Check yum configuration."
    exit 1
fi
log "Enabling and starting httpd and mariadb services..."
systemctl enable --now httpd &>> "$LOG_FILE"
systemctl enable --now mariadb &>> "$LOG_FILE"
log "Apache and MariaDB installed and started."
# Note: mysql_secure_installation is intentionally NOT run to leave a less secure default state for the competition.

# Step 3: Install and Configure PHP 7.2
log "Phase 3: PHP 7.2 Environment Configuration"
log "Installing EPEL and REMI repositories for PHP 7.2..."
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm &>> "$LOG_FILE"
yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm &>> "$LOG_FILE"
yum install -y yum-utils &>> "$LOG_FILE"

log "Enabling REMI repository for PHP 7.2..."
yum-config-manager --enable remi-php72 &>> "$LOG_FILE"

log "Installing PHP 7.2 and required extensions for PrestaShop..."
# This list is based on PrestaShop 1.7 system requirements
yum install -y php php-cli php-fpm php-mysqlnd php-zip php-devel php-gd php-mcrypt php-mbstring php-curl php-xml php-pear php-bcmath php-json php-opcache php-intl php-soap &>> "$LOG_FILE"
if [ $? -ne 0 ]; then
    log "ERROR: Failed to install PHP 7.2 or its extensions. Check repository configuration."
    exit 1
fi
log "PHP 7.2 and extensions installed successfully."

# Step 4: Automated Database and User Provisioning
log "Phase 4: Automated Database and User Provisioning"
log "Creating MariaDB database and user..."
# Using a here document for non-interactive SQL execution
mysql -u root <<-EOF
CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
if [ $? -eq 0 ]; then
    log "Database '${DB_NAME}' and user '${DB_USER}' created successfully."
else
    log "ERROR: Failed to create MariaDB database or user."
    exit 1
fi
# Note: GRANT ALL is intentionally overly permissive for the competition.

# Step 5: PrestaShop Application Deployment and Permissions
log "Phase 5: PrestaShop Application Deployment"
log "Downloading PrestaShop version ${PRESTASHOP_VERSION}..."
wget -O /tmp/prestashop.zip "$PRESTASHOP_URL" &>> "$LOG_FILE"
# Corrected: Added spaces for valid syntax
if [ ! -f /tmp/prestashop.zip ]; then
    log "ERROR: Failed to download PrestaShop zip file."
    exit 1
fi

log "Preparing web root directory..."
rm -rf ${WEB_ROOT}/*
unzip -o /tmp/prestashop.zip -d ${WEB_ROOT}/ &>> "$LOG_FILE"
# PrestaShop unzips into a 'prestashop' directory, we need to move contents up
mv ${WEB_ROOT}/prestashop/* ${WEB_ROOT}/
rm -rf ${WEB_ROOT}/prestashop
rm -f /tmp/prestashop.zip

log "Setting correct file and directory permissions..."
# These permissions are critical for the PrestaShop installer and runtime
find ${WEB_ROOT}/ -type d -exec chmod 755 {} \;
find ${WEB_ROOT}/ -type f -exec chmod 644 {} \;

log "Setting ownership to Apache user..."
chown -R apache:apache ${WEB_ROOT}

log "PrestaShop files deployed and permissions set."

# Step 6: Service Configuration and Finalization
log "Phase 6: Final Service Configuration"
log "Configuring Apache for PrestaShop..."
# Allow .htaccess overrides for PrestaShop's friendly URLs
sed -i '/<Directory "\/var\/www\/html">/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/httpd/conf/httpd.conf

log "Disabling SELinux..."
# SELinux can interfere with web server operations; disabling it is an intentional security reduction for the competition.
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

log "Restarting Apache to apply all changes..."
systemctl restart httpd

# --- Completion Message ---
SERVER_IP=$(hostname -I | awk '{print $1}')
log "INSTALLATION COMPLETE"
echo "========================================================================"
echo " PrestaShop Installation Script Finished"
echo "========================================================================"
echo ""
echo " The server is now ready for the final web-based installation step."
echo ""
echo " Please open a web browser and navigate to:"
echo "    http://${SERVER_IP}"
echo ""
echo " Use the following database credentials during the setup process:"
echo "    Database server address: 127.0.0.1"
echo "    Database name:           ${DB_NAME}"
echo "    Database user:           ${DB_USER}"
echo "    Database password:       ${DB_PASS}"
echo ""
echo " IMPORTANT: For security, you must delete the '/install' directory"
echo " located at ${WEB_ROOT}/install after the web setup is complete."
echo "========================================================================"

exit 0
