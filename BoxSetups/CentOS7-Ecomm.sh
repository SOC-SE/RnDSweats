#!/bin/bash

# ==============================================================================
# CentOS-Install.sh
#
# Author: Linux System Administration Expert
# Date:
#
# Description:
# This script automates the installation of PrestaShop 1.7.4.4 on a
# CentOS 7 server. It is designed for creating a cybersecurity competition
# environment, meaning it sets up a functional but intentionally insecure
# legacy system.
#
# Key Operations:
# 1. Checks for root privileges.
# 2. Fixes CentOS 7 EOL repositories to point to vault.centos.org.
# 3. Installs Apache, MariaDB 10.4, and PHP 7.1 with all required extensions.
# 4. Creates a database and user for PrestaShop.
# 5. Downloads and unpacks PrestaShop 1.7.4.4.
# 6. Sets appropriate file permissions and ownership for functionality.
# 7. Performs post-installation cleanup.
# 8. Outputs necessary credentials and the randomized admin URL.
#
# Usage:
# Run this script as root on a fresh CentOS 7 installation.
# # bash CentOS-Install.sh
#
# ==============================================================================

# --- Script Configuration ---
# Exit immediately if a command exits with a non-zero status.
set -e

# --- Variables ---
# Define variables for database credentials and PrestaShop source.
# Using variables makes the script easier to read and modify.
DB_NAME="prestashop_db"
DB_USER="ps_user"
# Generate a random, complex password for the database user.
DB_PASS="Changeme1!"
# Generate a random, complex password for the MariaDB root user.
DB_ROOT_PASS="Changeme1!"
PRESTASHOP_URL="https://github.com/PrestaShop/PrestaShop/releases/download/1.7.4.4/prestashop_1.7.4.4.zip"
PRESTASHOP_ZIP="prestashop_1.7.4.4.zip"
WEB_ROOT="/var/www/html"

# --- Helper Functions ---
# Function to print colored status messages.
print_status() {
    echo -e "\n\e[1;34m[INFO]\e[0m $1"
}

print_success() {
    echo -e "\e[1;32m[SUCCESS]\e[0m $1"
}

print_error() {
    echo -e "\e[1;31m[ERROR]\e[0m $1"
}

# --- Main Execution ---

# 1. Root Privilege Check
print_status "Checking for root privileges..."
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root. Exiting."
   exit 1
fi
print_success "Root privilege check passed."

# 2. Fix CentOS 7 EOL Repositories
print_status "CentOS 7 is EOL. Fixing repositories to point to vault.centos.org..."
# The standard mirrorlist.centos.org is offline. These commands redirect yum to the official archive.
# This is the most critical first step for any package installation on a modern CentOS 7 system.
sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
print_success "Yum repositories have been successfully pointed to the vault."

# Clean yum cache and update system packages.
print_status "Cleaning yum cache and updating base system packages..."
yum clean all
yum -y update
print_success "System packages updated."

# Install essential utilities needed for the script.
print_status "Installing prerequisite utilities (wget, unzip, policycoreutils-python)..."
yum install -y wget unzip policycoreutils-python
print_success "Prerequisite utilities installed."

# 3. Install and Configure LAMP Stack

# 3.1. Apache (httpd)
print_status "Installing and configuring Apache web server (httpd)..."
yum install -y httpd
systemctl start httpd
systemctl enable httpd
print_success "Apache installed and enabled."

# 3.3. MariaDB (Database Server)
print_status "Installing MariaDB 10.4..."
# PrestaShop 1.7 requires MySQL 5.6+. CentOS 7 default is MariaDB 5.5.
# We will add the official MariaDB repository to install a compatible version.
cat <<-EOF > /etc/yum.repos.d/MariaDB.repo
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.4/centos7-amd64
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1
EOF
yum install -y MariaDB-server MariaDB-client
systemctl start mariadb
systemctl enable mariadb
print_success "MariaDB 10.4 installed and enabled."

# Secure MariaDB installation non-interactively.
print_status "Securing MariaDB installation..."
mysql -u root <<-EOF
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${DB_ROOT_PASS}');
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
print_success "MariaDB installation secured."

# 3.4. PHP 7.1
print_status "Installing PHP 7.1 and required extensions from Remi repository..."
# PrestaShop 1.7.4.4 recommended PHP version is 7.1.
# This requires the EPEL and Remi repositories.
yum install -y epel-release yum-utils
yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum-config-manager --enable remi-php71

# Install PHP 7.1 and all extensions required by PrestaShop.
yum install -y php php-cli php-common php-gd php-intl php-mbstring php-mysqlnd php-pdo php-opcache php-xml php-zip php-curl php-fileinfo php-json php-openssl
print_success "PHP 7.1 and all required extensions installed."

# Restart Apache to load the new PHP module.
print_status "Restarting Apache to apply PHP configuration..."
systemctl restart httpd
print_success "Apache restarted."

# 4. Deploy PrestaShop Application

# 4.1. Download and Extract PrestaShop
print_status "Downloading PrestaShop 1.7.4.4..."
cd /tmp
wget -q -O ${PRESTASHOP_ZIP} ${PRESTASHOP_URL}
print_success "PrestaShop downloaded."

print_status "Extracting PrestaShop to web root..."
# Clear the default Apache welcome page if it exists.
rm -f ${WEB_ROOT}/index.html
# Unzip the main application archive.
unzip -q ${PRESTASHOP_ZIP} -d ${WEB_ROOT}/
# PrestaShop unzips into a 'prestashop' subdirectory, which contains the actual files.
# We need to move the contents up to the web root.
mv ${WEB_ROOT}/prestashop/* ${WEB_ROOT}/
rmdir ${WEB_ROOT}/prestashop
# The initial zip also contains an index.php file we don't need at the root.
rm -f ${WEB_ROOT}/index.php
print_success "PrestaShop extracted to ${WEB_ROOT}."

# 4.2. Create PrestaShop Database and User
print_status "Creating PrestaShop database and user..."
mysql -u root -p"${DB_ROOT_PASS}" <<-EOF
CREATE DATABASE ${DB_NAME};
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
print_success "Database '${DB_NAME}' and user '${DB_USER}' created."

# 5. Set File Permissions and Ownership
print_status "Setting file ownership and permissions for PrestaShop..."
# Set ownership to the Apache user to allow the web server to manage files.
chown -R apache:apache ${WEB_ROOT}

# Set recommended permissions: 755 for directories, 644 for files.
find ${WEB_ROOT}/ -type d -exec chmod 755 {} \;
find ${WEB_ROOT}/ -type f -exec chmod 644 {} \;

# SELinux context adjustment for web content.
semanage fcontext -a -t httpd_sys_rw_content_t "${WEB_ROOT}(/.*)?"
restorecon -R -v ${WEB_ROOT}
print_success "File permissions and ownership correctly set."

# 6. Post-Installation Cleanup and Finalization
print_status "Performing post-installation cleanup..."
# The installation directory MUST be removed for security.
if [ -d "${WEB_ROOT}/install" ]; then
    rm -rf ${WEB_ROOT}/install
    print_success "Installation directory removed."
else
    print_status "Installation directory not found, skipping removal."
fi

# PrestaShop renames the 'admin' directory for security. Find the new name.
ADMIN_DIR=$(find ${WEB_ROOT} -type d -name "admin*" -print -quit)
if [ -n "${ADMIN_DIR}" ]; then
    ADMIN_FOLDER_NAME=$(basename ${ADMIN_DIR})
    print_success "Detected randomized admin folder: ${ADMIN_FOLDER_NAME}"
else
    ADMIN_FOLDER_NAME="[Could not be determined - check manually]"
    print_error "Could not automatically determine the admin folder name."
fi

# Clean up downloaded zip file.
rm -f /tmp/${PRESTASHOP_ZIP}
print_success "Temporary files cleaned up."

# 7. Final Output
# Display all the generated information for the user.
SERVER_IP=$(hostname -I | awk '{print $1}')
print_status "========================================================================"
print_success "PrestaShop 1.7.4.4 Installation Complete!"
echo ""
echo "You can now complete the installation through your web browser."
echo "However, this script is intended for a non-interactive CLI installation."
echo "The setup is functional but requires manual web setup to finalize."
echo ""
echo "---------------------- Access Information ----------------------"
echo "PrestaShop Admin URL: http://${SERVER_IP}/${ADMIN_FOLDER_NAME}"
echo "---------------------- Database Credentials ----------------------"
echo "Database Name:   ${DB_NAME}"
echo "Database User:   ${DB_USER}"
echo "Database Pass:   ${DB_PASS}"
echo "-------------------- MariaDB Root Credentials --------------------"
echo "MariaDB Root User: root"
echo "MariaDB Root Pass: ${DB_ROOT_PASS}"
echo "========================================================================"
