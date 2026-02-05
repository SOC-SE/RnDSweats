#!/bin/bash
# ==============================================================================
# Script Name: mysqlharden.sh
# Description: MySQL hardening script - removes anonymous users, restricts
#              remote root, disables dangerous features, enables logging
# Author: Security Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./mysqlharden.sh [options]
#
# Options:
#   -h, --help           Show this help message
#   -u, --user           MySQL username (default: uses ~/.my.cnf)
#   -p, --password       MySQL password (will prompt if not provided)
#   -H, --host           MySQL host (default: localhost)
#   -r, --allow-remote   Skip binding to localhost (for remote-access servers)
#
# Prerequisites:
#   - MySQL client installed
#   - Either ~/.my.cnf configured or credentials provided
#   - Root/sudo access for config file changes
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - MySQL connection failed
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
MYSQL_USER=""
MYSQL_PASS=""
MYSQL_HOST="localhost"
ALLOW_REMOTE=false
CNF_FILE="$HOME/.my.cnf"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -30 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
}

prompt_password() {
    local user_label=$1
    local var_name=$2
    while true; do
        echo -n "Enter new password for $user_label: "
        stty -echo
        read -r pass1
        stty echo
        echo
        echo -n "Confirm new password for $user_label: "
        stty -echo
        read -r pass2
        stty echo
        echo

        if [ "$pass1" == "$pass2" ] && [ -n "$pass1" ]; then
            declare -g "$var_name=$pass1"
            break
        else
            echo "Passwords do not match or are empty. Try again."
        fi
    done
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -u|--user)
            MYSQL_USER="$2"
            shift 2
            ;;
        -p|--password)
            MYSQL_PASS="$2"
            shift 2
            ;;
        -H|--host)
            MYSQL_HOST="$2"
            shift 2
            ;;
        -r|--allow-remote)
            ALLOW_REMOTE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (needed for config file changes)"
    exit 1
fi

# --- Build MySQL command ---
build_mysql_cmd() {
    local cmd="mysql"

    if [[ -n "$MYSQL_USER" ]]; then
        cmd="$cmd -u $MYSQL_USER"
        if [[ -n "$MYSQL_PASS" ]]; then
            cmd="$cmd -p$MYSQL_PASS"
        fi
    elif [[ -f "$CNF_FILE" ]]; then
        cmd="$cmd --defaults-extra-file=$CNF_FILE"
    elif mysql -u root -e "SELECT 1" &>/dev/null; then
        # Socket auth works as root (common on MariaDB/Fedora)
        cmd="$cmd -u root"
    else
        error "No credentials provided. Use -u/-p or create ~/.my.cnf"
        exit 1
    fi

    cmd="$cmd -h $MYSQL_HOST"
    echo "$cmd"
}

MYSQL_CMD=$(build_mysql_cmd)

# --- Test connection ---
log "Testing MySQL connection to $MYSQL_HOST..."
if ! $MYSQL_CMD -e "SELECT 1" &>/dev/null; then
    error "Failed to connect to MySQL"
    exit 2
fi
log "Connection successful"

echo ""
echo "========================================"
echo "MYSQL HARDENING"
echo "========================================"
echo ""

# --- 0. MySQL Root Password Rotation ---
log "Phase 0: MySQL Root Password Rotation"
echo ""
echo "Do you want to change the MySQL root password? (y/n)"
read -r change_root_pass

if [[ "$change_root_pass" =~ ^[Yy]$ ]]; then
    prompt_password "MySQL root" NEW_MYSQL_ROOT_PASS

    log "Changing MySQL root password..."

    # Get all root user hosts
    root_hosts=$($MYSQL_CMD -N -e "SELECT Host FROM mysql.user WHERE User='root';" 2>/dev/null)

    if [[ -n "$root_hosts" ]]; then
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            # Use ALTER USER for MySQL 5.7+ / MariaDB 10.2+
            if $MYSQL_CMD -e "ALTER USER 'root'@'$host' IDENTIFIED BY '$NEW_MYSQL_ROOT_PASS';" 2>/dev/null; then
                log "Updated root@$host password"
            else
                # Fallback for older MySQL versions
                $MYSQL_CMD -e "SET PASSWORD FOR 'root'@'$host' = PASSWORD('$NEW_MYSQL_ROOT_PASS');" 2>/dev/null && \
                    log "Updated root@$host password (legacy method)" || \
                    warn "Failed to update root@$host password"
            fi
        done <<< "$root_hosts"

        $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null
        log "Root password changed successfully"

        # Update ~/.my.cnf if it exists
        if [[ -f "$CNF_FILE" ]]; then
            log "Updating $CNF_FILE with new password..."
            # Backup the cnf file
            cp "$CNF_FILE" "${CNF_FILE}.bak.$(date +%Y%m%d%H%M%S)"
            # Update password in [client] section
            if grep -q "^password" "$CNF_FILE" 2>/dev/null; then
                sed -i "s/^password.*/password=$NEW_MYSQL_ROOT_PASS/" "$CNF_FILE"
            elif grep -q "^\[client\]" "$CNF_FILE" 2>/dev/null; then
                sed -i "/^\[client\]/a password=$NEW_MYSQL_ROOT_PASS" "$CNF_FILE"
            fi
            chmod 600 "$CNF_FILE"
            log "Updated $CNF_FILE"
        fi

        # Rebuild MySQL command with new password for remaining operations
        if [[ -n "$MYSQL_USER" ]]; then
            MYSQL_CMD="mysql -u $MYSQL_USER -p$NEW_MYSQL_ROOT_PASS -h $MYSQL_HOST"
        elif [[ -f "$CNF_FILE" ]]; then
            # CNF file was updated, command should still work
            MYSQL_CMD="mysql --defaults-extra-file=$CNF_FILE -h $MYSQL_HOST"
        fi

        # Verify new password works
        if ! $MYSQL_CMD -e "SELECT 1" &>/dev/null; then
            critical "Failed to connect with new password! Check credentials manually."
            exit 2
        fi
        log "Verified connection with new password"
    else
        warn "No root users found in mysql.user table"
    fi
else
    log "Skipping root password change"
fi

echo ""

# --- 1. Remove anonymous users ---
log "Removing anonymous users..."
anon_count=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" 2>/dev/null)
if [[ "$anon_count" -gt 0 ]]; then
    $MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null
    log "Removed $anon_count anonymous user(s)"
else
    log "No anonymous users found"
fi

# --- 2. Remove test database ---
log "Removing test database..."
test_exists=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';" 2>/dev/null)
if [[ "$test_exists" -gt 0 ]]; then
    $MYSQL_CMD -e "DROP DATABASE IF EXISTS test;" 2>/dev/null
    $MYSQL_CMD -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null
    log "Removed test database and related privileges"
else
    log "No test database found"
fi

# --- 3. Disable remote root login ---
log "Disabling remote root login..."
remote_root=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null)
if [[ "$remote_root" -gt 0 ]]; then
    $MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null
    log "Removed $remote_root remote root login(s)"
else
    log "No remote root logins found"
fi

# --- 4. Revoke dangerous privileges from non-root users ---
log "Checking for dangerous privileges on non-root users..."
dangerous_users=$($MYSQL_CMD -N -e "
    SELECT CONCAT(User, '@', Host) FROM mysql.user
    WHERE User != 'root' AND User != '' AND User != 'mysql.sys' AND User != 'mysql.session' AND User != 'mysql.infoschema'
    AND (File_priv='Y' OR Super_priv='Y' OR Process_priv='Y' OR Shutdown_priv='Y' OR Create_user_priv='Y');" 2>/dev/null)

if [[ -n "$dangerous_users" ]]; then
    while IFS= read -r userhost; do
        [[ -z "$userhost" ]] && continue
        user=$(echo "$userhost" | cut -d'@' -f1)
        host=$(echo "$userhost" | cut -d'@' -f2)
        warn "Revoking dangerous privileges from '$user'@'$host'"
        $MYSQL_CMD -e "UPDATE mysql.user SET File_priv='N', Super_priv='N', Process_priv='N', Shutdown_priv='N', Create_user_priv='N' WHERE User='$user' AND Host='$host';" 2>/dev/null
    done <<< "$dangerous_users"
    log "Dangerous privileges revoked"
else
    log "No non-root users with dangerous privileges"
fi

# --- 5. Disable local_infile ---
log "Disabling local_infile..."
$MYSQL_CMD -e "SET GLOBAL local_infile = 0;" 2>/dev/null
log "local_infile disabled at runtime"

# --- 6 & 7. Config file hardening ---
MYSQL_CONF=""
for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf.d/mariadb-server.cnf /etc/my.cnf; do
    if [[ -f "$conf" ]]; then
        MYSQL_CONF="$conf"
        break
    fi
done

if [[ -n "$MYSQL_CONF" ]]; then
    log "Hardening config file: $MYSQL_CONF"

    # Backup config
    cp "$MYSQL_CONF" "${MYSQL_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    log "Config backed up"

    # Disable symbolic-links
    if grep -q "^symbolic-links" "$MYSQL_CONF" 2>/dev/null; then
        sed -i 's/^symbolic-links.*/symbolic-links=0/' "$MYSQL_CONF"
    elif grep -q "^\[mysqld\]" "$MYSQL_CONF" 2>/dev/null; then
        sed -i '/^\[mysqld\]/a symbolic-links=0' "$MYSQL_CONF"
    fi
    log "symbolic-links disabled"

    # Disable local_infile in config
    if grep -q "^local.infile" "$MYSQL_CONF" 2>/dev/null; then
        sed -i 's/^local.infile.*/local-infile=0/' "$MYSQL_CONF"
    elif grep -q "^\[mysqld\]" "$MYSQL_CONF" 2>/dev/null; then
        sed -i '/^\[mysqld\]/a local-infile=0' "$MYSQL_CONF"
    fi
    log "local-infile=0 set in config"

    # Bind to localhost
    if [[ "$ALLOW_REMOTE" == "false" ]]; then
        if grep -q "^bind-address" "$MYSQL_CONF" 2>/dev/null; then
            sed -i 's/^bind-address.*/bind-address=127.0.0.1/' "$MYSQL_CONF"
        elif grep -q "^\[mysqld\]" "$MYSQL_CONF" 2>/dev/null; then
            sed -i '/^\[mysqld\]/a bind-address=127.0.0.1' "$MYSQL_CONF"
        fi
        log "bind-address set to 127.0.0.1"
    else
        warn "Skipping bind-address (--allow-remote specified)"
    fi

    # Enable logging in config
    if ! grep -q "^general_log" "$MYSQL_CONF" 2>/dev/null; then
        if grep -q "^\[mysqld\]" "$MYSQL_CONF" 2>/dev/null; then
            sed -i '/^\[mysqld\]/a general_log=1\ngeneral_log_file=/var/log/mysql/mysql.log' "$MYSQL_CONF"
        fi
    fi
    if ! grep -q "^log_error" "$MYSQL_CONF" 2>/dev/null; then
        if grep -q "^\[mysqld\]" "$MYSQL_CONF" 2>/dev/null; then
            sed -i '/^\[mysqld\]/a log_error=/var/log/mysql/error.log' "$MYSQL_CONF"
        fi
    fi
    log "Logging configured"

    # --- 9. Secure file permissions ---
    chmod 640 "$MYSQL_CONF"
    chown mysql:mysql "$MYSQL_CONF" 2>/dev/null || chown root:mysql "$MYSQL_CONF" 2>/dev/null
    log "Config file permissions set to 640"
else
    warn "MySQL config file not found - skipping file-based hardening"
fi

# --- 8. Enable logging at runtime ---
log "Enabling logging at runtime..."
$MYSQL_CMD -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
$MYSQL_CMD -e "SET GLOBAL log_output = 'FILE';" 2>/dev/null
log "Runtime logging enabled"

# --- 10. Flush privileges ---
log "Flushing privileges..."
$MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null
log "Privileges flushed"

echo ""
echo "========================================"
echo "MYSQL HARDENING COMPLETE"
echo "========================================"
echo ""
warn "Restart MySQL to apply config file changes: systemctl restart mysql"

exit 0
