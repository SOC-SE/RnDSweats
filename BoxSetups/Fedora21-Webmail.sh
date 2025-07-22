#!/bin/bash

# ==============================================================================
# Fedora-Install.sh
#
# Author: Linux System Administration Expert
# Date:   July 21, 2025
#
# Description:
# This script automates the installation and basic configuration of a
# Postfix, Dovecot, and Roundcube mail stack on a fresh Fedora 21 system.
# It is specifically designed for a cybersecurity competition environment,
# where the initial configuration is required to be functional but insecure.
#
# Pre-requisites:
# - A fresh, minimal installation of Fedora 21 (x86_64).
# - Internet connectivity.
# - The script must be run with root privileges (e.g., using sudo).
#
# ==============================================================================

# --- Variable Definitions ---
# Centralizing variables makes the script easier to read and modify.
HOSTNAME_FQDN="webmail.comp.local"
DOMAIN="comp.local"
SYS_USER="sysadmin"
SYS_PASS="Changeme1!"
DB_ROOT_PASS="Changeme1!"
RCUBE_DB="rcube"
RCUBE_USER="roundcube"
RCUBE_PASS="Changeme1!"
LOG_FILE="/var/log/Fedora-Install.log"

# --- Helper Functions ---

# Function to log messages to both console and a log file
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to check if the script is run as root
check_root() {
    # This correctly checks if the effective user ID is not 0 (root)
    if [ "$(id -u)" -ne 0 ]; then
        log_message "ERROR: This script must be run as root."
        exit 1
    fi
}

# --- Main Execution ---

# Ensure the script is run with root privileges
check_root

# Start logging
log_message "Starting mail server deployment script."

# --- Stage 1: System Prerequisites and EOL Repository Fix ---
log_message "Stage 1: Configuring system prerequisites..."

# Set the system hostname
log_message "Setting hostname to $HOSTNAME_FQDN..."
hostnamectl set-hostname "$HOSTNAME_FQDN"

# Update /etc/hosts to ensure local resolution
log_message "Updating /etc/hosts..."
sed -i "/^127.0.0.1/ s/$/ $HOSTNAME_FQDN $DOMAIN/" /etc/hosts

# Create the competition user and set password
log_message "Creating user '$SYS_USER'..."
# This correctly checks if the user does NOT exist before attempting creation
if ! id "$SYS_USER" &>/dev/null; then
    useradd "$SYS_USER"
    echo "$SYS_USER:$SYS_PASS" | chpasswd
    log_message "User '$SYS_USER' created with the specified password."
else
    log_message "User '$SYS_USER' already exists. Skipping creation."
fi

# Fedora 21 is End-of-Life. The standard repositories are offline.
# We must reconfigure yum to point to the official Fedora archives.
log_message "Reconfiguring yum repositories for EOL Fedora 21..."
# Backup original repo files
mkdir -p /etc/yum.repos.d/original
mv /etc/yum.repos.d/fedora* /etc/yum.repos.d/original/

# Create new repo file for the archives
cat > /etc/yum.repos.d/fedora-archive.repo << EOF
[fedora-archive]
name=Fedora 21 - x86_64 - Archive
baseurl=http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/21/Everything/x86_64/os/
enabled=1
gpgcheck=0

[updates-archive]
name=Fedora 21 - x86_64 - Updates Archive
baseurl=http://archives.fedoraproject.org/pub/archive/fedora/linux/updates/21/x86_64/
enabled=1
gpgcheck=0
EOF

log_message "Yum repositories reconfigured. Cleaning yum cache..."
yum clean all
log_message "Prerequisites stage complete."

# --- Stage 2: Package Installation ---
log_message "Stage 2: Installing core service packages..."

# Install all necessary packages in a single transaction.
PACKAGES=(
    postfix
    dovecot
    httpd
    mariadb-server
    php
    php-cli
    php-gettext
    php-mbstring
    php-mcrypt
    php-mysqlnd
    php-pear
    php-curl
    php-gd
    php-xml
    php-bcmath
    php-zip
    roundcubemail
)

log_message "Installing the following packages: ${PACKAGES[*]}"
yum install -y "${PACKAGES[@]}" >> "$LOG_FILE" 2>&1
# This correctly checks the exit status of the yum command
if [ $? -ne 0 ]; then
    log_message "ERROR: Package installation failed. Check $LOG_FILE for details."
    exit 1
fi
log_message "Package installation complete."

# --- Stage 3: MariaDB Configuration (Corrected) ---
log_message "Stage 3: Configuring MariaDB..."

# Start MariaDB to perform initial configuration
systemctl start mariadb
systemctl enable mariadb

# CORRECTED: Set the root password using mysqladmin first for reliability
log_message "Setting MariaDB root password..."
mysqladmin -u root password "$DB_ROOT_PASS"

# Now execute the rest of the security steps using the new password
log_message "Securing MariaDB installation..."
mysql -u root -p"$DB_ROOT_PASS" <<-EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

log_message "MariaDB secured."

# Create the Roundcube database and user
log_message "Creating Roundcube database '$RCUBE_DB' and user '$RCUBE_USER'..."
mysql -u root -p"$DB_ROOT_PASS" <<-EOF
CREATE DATABASE $RCUBE_DB;
CREATE USER '$RCUBE_USER'@'localhost' IDENTIFIED BY '$RCUBE_PASS';
GRANT ALL PRIVILEGES ON $RCUBE_DB.* TO '$RCUBE_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

log_message "Roundcube database and user created successfully."
log_message "MariaDB configuration complete."

# --- Stage 4: Postfix Configuration ---
log_message "Stage 4: Configuring Postfix..."

# Use postconf for robust, idempotent configuration of /etc/postfix/main.cf
log_message "Configuring /etc/postfix/main.cf..."
postconf -e "myhostname = $HOSTNAME_FQDN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
postconf -e "home_mailbox = Maildir/"

# Configure Postfix to use Dovecot for SASL authentication
log_message "Configuring Postfix for Dovecot SASL..."
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"

# No TLS for this insecure setup
postconf -e "smtpd_use_tls = no"
postconf -e "smtp_use_tls = no"

log_message "Postfix configuration complete."

# --- Stage 5: Dovecot Configuration ---
log_message "Stage 5: Configuring Dovecot..."

# Configure /etc/dovecot/dovecot.conf
log_message "Configuring main dovecot.conf..."
sed -i 's/^#protocols = .*/protocols = imap pop3 lmtp/' /etc/dovecot/dovecot.conf
sed -i 's/^#listen = .*/listen = *, ::/' /etc/dovecot/dovecot.conf

# Configure /etc/dovecot/conf.d/10-auth.conf for plaintext authentication
log_message "Configuring 10-auth.conf for insecure plaintext auth..."
sed -i 's/^disable_plaintext_auth = .*/disable_plaintext_auth = no/' /etc/dovecot/conf.d/10-auth.conf
sed -i 's/^auth_mechanisms = .*/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf

# Configure /etc/dovecot/conf.d/10-mail.conf for Maildir
log_message "Configuring 10-mail.conf for Maildir storage..."
sed -i 's|^#mail_location = .*|mail_location = maildir:~/Maildir|' /etc/dovecot/conf.d/10-mail.conf

# Configure /etc/dovecot/conf.d/10-ssl.conf to disable SSL/TLS
log_message "Configuring 10-ssl.conf to disable SSL..."
sed -i 's/^ssl = .*/ssl = no/' /etc/dovecot/conf.d/10-ssl.conf

# Configure /etc/dovecot/conf.d/10-master.conf for Postfix authentication socket
log_message "Configuring 10-master.conf for Postfix auth socket..."
# IMPROVED: This sed command is more robust than the original awk script.
# It finds the 'service auth {' line and appends the unix_listener block.
sed -i '/service auth {/a \
  # Postfix smtp-auth\
  unix_listener /var/spool/postfix/private/auth {\
    mode = 0666\
    user = postfix\
    group = postfix\
  }' /etc/dovecot/conf.d/10-master.conf

log_message "Dovecot configuration complete."

# --- Stage 6: Roundcube Configuration (Corrected) ---
log_message "Stage 6: Configuring Roundcube..."

# Import the initial database schema
log_message "Importing Roundcube SQL schema..."
mysql -u "$RCUBE_USER" -p"$RCUBE_PASS" "$RCUBE_DB" < /usr/share/roundcubemail/SQL/mysql.initial.sql

# Create the config file from the default template
cp /etc/roundcubemail/defaults.inc.php /etc/roundcubemail/config.inc.php

# Configure the database connection and mail server settings
log_message "Configuring /etc/roundcubemail/config.inc.php..."
CONFIG_FILE="/etc/roundcubemail/config.inc.php"

# IMPROVED: Consolidated and anchored sed commands for clarity and reliability.
sed -i "s|^\$config\['db_dsnw'\].*|\$config\['db_dsnw'\] = 'mysql://$RCUBE_USER:$RCUBE_PASS@localhost/$RCUBE_DB';|" "$CONFIG_FILE"
sed -i "s|^\$config\['default_host'\].*|\$config\['default_host'\] = 'localhost';|" "$CONFIG_FILE"
sed -i "s|^\$config\['smtp_server'\].*|\$config\['smtp_server'\] = 'localhost';|" "$CONFIG_FILE"
sed -i "s|^\$config\['smtp_port'\].*|\$config\['smtp_port'\] = 25;|" "$CONFIG_FILE"
sed -i "s|^\$config\['smtp_user'\].*|\$config\['smtp_user'\] = '%u';|" "$CONFIG_FILE"
sed -i "s|^\$config\['smtp_pass'\].*|\$config\['smtp_pass'\] = '%p';|" "$CONFIG_FILE"
sed -i "s|^\$config\['support_url'\].*|\$config\['support_url'\] = 'http://$HOSTNAME_FQDN';|" "$CONFIG_FILE"
sed -i "s|^\$config\['product_name'\].*|\$config\['product_name'\] = 'Comp Local Webmail';|" "$CONFIG_FILE"
sed -i "/^\$config\['default_host'\].*/a \$config['imap_auth_type'] = 'LOGIN';\n\$config['smtp_auth_type'] = 'LOGIN';" "$CONFIG_FILE"


# Configure Apache for Roundcube
log_message "Configuring Apache for Roundcube access..."
# The default roundcubemail.conf may restrict access. We will make it open.
sed -i "s/Require ip 127.0.0.1/Require all granted/" /etc/httpd/conf.d/roundcubemail.conf
sed -i "s/Require ip ::1/ /" /etc/httpd/conf.d/roundcubemail.conf

# Set SELinux boolean to allow HTTPD to make network connections (for SMTP/IMAP)
log_message "Setting SELinux policy for HTTPD network connections..."
setsebool -P httpd_can_network_connect on

log_message "Roundcube configuration complete."

# --- Stage 7: Service Finalization ---
log_message "Stage 7: Starting and enabling all services..."

# Start and enable all services to run on boot
systemctl enable httpd
systemctl start httpd
log_message "httpd service started and enabled."

systemctl enable postfix
systemctl start postfix
log_message "postfix service started and enabled."

systemctl enable dovecot
systemctl start dovecot
log_message "dovecot service started and enabled."

# Flush all rules and set the default policies to ACCEPT for the current session.
# This ensures immediate open access.
log_message "Flushing all current iptables rules and setting policies to ACCEPT..."
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
log_message "Saving empty 'allow all' ruleset to /etc/sysconfig/iptables..."
iptables-save > /etc/sysconfig/iptables

log_message "All services have been configured, started, and enabled."
log_message "Deployment script finished successfully."
echo ""
echo "------------------------------------------------------------------"
echo "Mail Server Installation Complete!"
echo "Access Roundcube at: http://$HOSTNAME_FQDN/roundcubemail"
echo "Login with user: $SYS_USER"
echo "Password: $SYS_PASS"
echo "------------------------------------------------------------------"

exit 0
