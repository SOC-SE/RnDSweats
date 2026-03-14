#!/bin/bash
#
# SQL Hardening Script (Ubuntu & Fedora)
# Supports MySQL & MariaDB
#
# FEATURES:
# 1. Backups:
#    - Creates a backup of SQL configs, databases
# 2. Hardening:
#    - Adds basic hardening configs for SQL
# 3. Rollback:
#    - Allows loading from backups, reverting hardening
#
# Not tested on competition environment yet

BACKUP_BASE="/var/backups/mysql_hardening"
DB_BACKUP="$BACKUP_BASE/databases"
CONF_BACKUP="$BACKUP_BASE/configs"

AUDIT_RULE_FILE="/etc/audit/rules.d/mysql-hardening.rules"

HARDEN_MARK="/var/lib/mysql/.hardening_done"

TIME=$(date +"%H-%M-%S")

MYSQL=$(command -v mysql)
MYSQLDUMP=$(command -v mysqldump)
MYSQLD_BIN=$(command -v mysqld)

mkdir -p "$DB_BACKUP"
mkdir -p "$CONF_BACKUP"

#############################################

detect_paths(){

if [ -d /etc/mysql/mysql.conf.d ]; then
    HARDEN_CONF="/etc/mysql/mysql.conf.d/99-security-hardening.cnf"
elif [ -d /etc/my.cnf.d ]; then
    HARDEN_CONF="/etc/my.cnf.d/99-security-hardening.cnf"
else
    HARDEN_CONF="/etc/my.cnf"
fi

if [ -d /var/log/mysql ]; then
    MYSQL_LOG_DIR="/var/log/mysql"
else
    MYSQL_LOG_DIR="/var/log"
fi

}

#############################################

detect_service(){

if systemctl list-units --type=service | grep -q mariadb; then
    MYSQL_SERVICE="mariadb"
else
    MYSQL_SERVICE="mysql"
fi

}

#############################################

install_auditd(){

if command -v auditctl >/dev/null; then
    return
fi

echo "Installing auditd..."

if command -v apt >/dev/null; then
    apt update
    apt install -y auditd audispd-plugins
elif command -v dnf >/dev/null; then
    dnf install -y audit audit-libs
fi

}

#############################################

create_backups(){

echo "Creating backups..."

TMP_DB=$(mktemp -d)

DATABASES=$($MYSQL -N -e "SHOW DATABASES;" \
| grep -Ev "^(information_schema|performance_schema|sys)$")

for db in $DATABASES
do
    echo "Backing up DB: $db"
    $MYSQLDUMP --databases "$db" > "$TMP_DB/$db.sql"
done

tar -czf "$DB_BACKUP/mysql_dbs_$TIME.tar.gz" -C "$TMP_DB" .

rm -rf "$TMP_DB"

CONF_LIST=()

[ -f /etc/mysql/my.cnf ] && CONF_LIST+=("/etc/mysql/my.cnf")
[ -d /etc/mysql/mysql.conf.d ] && CONF_LIST+=("/etc/mysql/mysql.conf.d")
[ -d /etc/mysql/mariadb.conf.d ] && CONF_LIST+=("/etc/mysql/mariadb.conf.d")
[ -f /etc/my.cnf ] && CONF_LIST+=("/etc/my.cnf")
[ -d /etc/my.cnf.d ] && CONF_LIST+=("/etc/my.cnf.d")

tar -czf "$CONF_BACKUP/mysql_configs_$TIME.tar.gz" "${CONF_LIST[@]}"

echo "Backups completed."

}

#############################################

secure_mysql_accounts(){

echo "Securing MySQL accounts..."

$MYSQL <<EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

}

#############################################

configure_server(){

echo "Applying server hardening..."

mkdir -p /var/lib/mysql-secure-files
chown mysql:mysql /var/lib/mysql-secure-files
chmod 750 /var/lib/mysql-secure-files

cat <<EOF > "$HARDEN_CONF"
[mysqld]

symbolic-links=0
local-infile=0
skip-name-resolve
skip-show-database
max_connect_errors=100
secure-file-priv=/var/lib/mysql-secure-files

sql_mode=STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION

slow_query_log=1
slow_query_log_file=$MYSQL_LOG_DIR/mysql-slow.log
long_query_time=2

log_error_verbosity=2

EOF

touch "$HARDEN_MARK"

}

#############################################

secure_permissions(){

echo "Securing file permissions..."

chmod 640 /etc/mysql/my.cnf 2>/dev/null
chmod -R 750 /etc/mysql/mysql.conf.d 2>/dev/null
chmod -R 750 /etc/mysql/mariadb.conf.d 2>/dev/null
chmod 640 /etc/my.cnf 2>/dev/null
chmod -R 750 /etc/my.cnf.d 2>/dev/null

chown -R mysql:mysql /var/lib/mysql 2>/dev/null

}

#############################################

configure_auditd(){

echo "Configuring auditd..."

install_auditd

systemctl enable auditd
systemctl start auditd

cat <<EOF > $AUDIT_RULE_FILE

-w /etc/mysql/ -p wa -k mysql_config_change
-w /etc/my.cnf -p wa -k mysql_config_change
-w /etc/my.cnf.d/ -p wa -k mysql_config_change

-w /var/lib/mysql/ -p wa -k mysql_db_access

-w $MYSQL_LOG_DIR -p wa -k mysql_log_access

-w $MYSQL -p x -k mysql_command
-w $MYSQLDUMP -p x -k mysql_dump
-w $MYSQLD_BIN -p x -k mysql_daemon

-w /etc/passwd -p wa -k user_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes

EOF

augenrules --load

systemctl restart auditd

}

#############################################

change_root_password(){

echo ""
echo "Configure SQL root password"

while true
do
    read -s -p "Enter new root password: " PASS1
    echo
    read -s -p "Confirm new root password: " PASS2
    echo

    if [ "$PASS1" != "$PASS2" ]; then
        echo "Passwords do not match. Try again."
    elif [ -z "$PASS1" ]; then
        echo "Password cannot be empty."
    else
        break
    fi
done

echo "Updating root password..."

$MYSQL <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$PASS1';
FLUSH PRIVILEGES;
EOF

if [ $? -eq 0 ]; then
    echo "Root password successfully updated."
else
    echo "Password update may have failed. Verify manually."
fi

unset PASS1
unset PASS2

}

#############################################

perform_hardening(){

detect_service
detect_paths

echo "Starting hardening..."

create_backups
secure_mysql_accounts
change_root_password
configure_server
secure_permissions
configure_auditd

systemctl restart "$MYSQL_SERVICE"

echo "Hardening completed."

}

#############################################

load_backups(){

echo ""
echo "1) Restore database backups"
echo "2) Restore configuration backups"
read -p "Choice: " c

detect_service

if [ "$c" == "1" ]; then

LATEST=$(ls -t $DB_BACKUP/*.tar.gz 2>/dev/null | head -1)

[ -z "$LATEST" ] && echo "No backups found." && return

TMP=$(mktemp -d)

tar -xzf "$LATEST" -C "$TMP"

for f in $TMP/*.sql
do
echo "Restoring $f"
$MYSQL < "$f"
done

rm -rf "$TMP"

echo "Database restore complete."

elif [ "$c" == "2" ]; then

LATEST=$(ls -t $CONF_BACKUP/*.tar.gz 2>/dev/null | head -1)

[ -z "$LATEST" ] && echo "No backups found." && return

tar -xzf "$LATEST" -C /

systemctl restart "$MYSQL_SERVICE"

echo "Configuration restore complete."

fi

}

#############################################

revert_hardening(){

detect_service
detect_paths

if [ ! -f "$HARDEN_MARK" ]; then
echo "Hardening not applied."
return
fi

rm -f "$HARDEN_CONF"

rm -f "$HARDEN_MARK"

systemctl restart "$MYSQL_SERVICE"

if [ -f "$AUDIT_RULE_FILE" ]; then
rm -f "$AUDIT_RULE_FILE"
augenrules --load
fi

echo "Hardening reverted."

}

#############################################

menu(){

while true
do

echo ""
echo "================================="
echo " MySQL / MariaDB Hardening Tool"
echo "================================="
echo "1) Create Backups"
echo "2) Perform Hardening"
echo "3) Load Backups"
echo "4) Revert Hardening"
echo "5) Exit"
echo ""

read -p "Select option: " opt

case $opt in
1) create_backups ;;
2) perform_hardening ;;
3) load_backups ;;
4) revert_hardening ;;
5) exit 0 ;;
*) echo "Invalid option" ;;
esac

done

}

menu
