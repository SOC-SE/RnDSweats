#!/bin/bash
# ==============================================================================
# Script Name: mysqlenum.sh
# Description: MySQL security audit script with automatic logging enablement
#              and dangerous privilege detection
# Author: CCDC Team
# Date: 2025-2026
# Version: 2.0
#
# Usage:
#   ./mysqlenum.sh [options]
#
# Options:
#   -h, --help           Show this help message
#   -u, --user           MySQL username (default: uses ~/.my.cnf)
#   -p, --password       MySQL password (will prompt if not provided)
#   -H, --host           MySQL host (default: localhost)
#   -e, --enable-logs    Enable MySQL general logging
#   -o, --output         Output file (default: mysql_audit_report.txt)
#
# Prerequisites:
#   - MySQL client installed
#   - Either ~/.my.cnf configured or credentials provided
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
ENABLE_LOGS=false
OUTPUT_FILE="$(dirname "$0")/mysql_audit_report.txt"
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
        -e|--enable-logs)
            ENABLE_LOGS=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

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

# --- Main Audit ---
{
    echo "========================================================"
    echo "MYSQL SECURITY AUDIT REPORT"
    echo "Host: $MYSQL_HOST"
    echo "Date: $(date)"
    echo "========================================================"
    echo ""

    # Enable logging if requested
    if [[ "$ENABLE_LOGS" == "true" ]]; then
        echo "--- ENABLING MYSQL LOGGING ---"
        $MYSQL_CMD -e "SET GLOBAL general_log = 'ON';" 2>&1
        $MYSQL_CMD -e "SET GLOBAL log_output = 'FILE';" 2>&1
        $MYSQL_CMD -e "SET GLOBAL general_log_file = '/var/log/mysql/mysql.log';" 2>&1 || \
        $MYSQL_CMD -e "SET GLOBAL general_log_file = '/var/log/mysql.log';" 2>&1
        echo "MySQL general logging enabled"
        echo ""
    fi

    # Show current logging status
    echo "--- LOGGING STATUS ---"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'general_log%';"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'log_output';"
    echo ""

    # Server version and configuration
    echo "--- SERVER INFORMATION ---"
    $MYSQL_CMD -t -e "SELECT VERSION() AS 'MySQL Version';"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'hostname';"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'datadir';"
    echo ""

    # Security settings
    echo "--- SECURITY SETTINGS ---"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'local_infile';"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'secure_file_priv';"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'skip_networking';"
    $MYSQL_CMD -t -e "SHOW VARIABLES LIKE 'bind_address';"
    echo ""

    # List databases
    echo "--- DATABASES ---"
    $MYSQL_CMD -t -e "SHOW DATABASES;"
    echo ""

    # List all users
    echo "--- ALL USERS ---"
    $MYSQL_CMD -t -e "SELECT User, Host, plugin, password_expired, account_locked FROM mysql.user ORDER BY User;"
    echo ""

    # Users and permissions
    echo "--- USER PERMISSIONS ---"
    USER_LIST=$($MYSQL_CMD -N -e "SELECT CONCAT(\"'\", User, \"'@'\", Host, \"'\") FROM mysql.user")

    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        echo "=========================================="
        echo "User: $user"
        echo "=========================================="

        # Check for anonymous user
        if [[ "$user" == *"''@"* ]]; then
            echo "*** WARNING: This is an ANONYMOUS user - security risk! ***"
        fi

        echo "Grants:"
        $MYSQL_CMD -N -e "SHOW GRANTS FOR $user;" 2>&1 | sed 's/^/  /'
        echo ""
    done <<< "$USER_LIST"

    # Dangerous privileges audit
    echo "========================================================"
    echo "DANGEROUS PRIVILEGES AUDIT"
    echo "========================================================"
    echo ""

    echo "--- USERS WITH SUPER PRIVILEGE ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Super_priv='Y';"
    echo ""

    echo "--- USERS WITH FILE PRIVILEGE (can read/write files) ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE File_priv='Y';"
    echo ""

    echo "--- USERS WITH PROCESS PRIVILEGE (can see all queries) ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Process_priv='Y';"
    echo ""

    echo "--- USERS WITH GRANT PRIVILEGE (can grant to others) ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Grant_priv='Y';"
    echo ""

    echo "--- USERS WITH DROP/ALTER PRIVILEGES (destructive) ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Drop_priv='Y' OR Alter_priv='Y';"
    echo ""

    echo "--- USERS WITH SHUTDOWN PRIVILEGE ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Shutdown_priv='Y';"
    echo ""

    echo "--- USERS WITH CREATE USER PRIVILEGE ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Create_user_priv='Y';"
    echo ""

    echo "--- USERS WITH WILDCARD HOST (%) ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Host='%';"
    echo ""

    echo "--- ANONYMOUS USERS (empty username) ---"
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE User='';"
    echo ""

    echo "--- USERS WITH NO PASSWORD ---"
    # Works for MySQL 5.7+
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;" 2>/dev/null || \
    $MYSQL_CMD -t -e "SELECT User, Host FROM mysql.user WHERE Password='';" 2>/dev/null
    echo ""

    # Database-level privileges
    echo "========================================================"
    echo "DATABASE-LEVEL PRIVILEGES"
    echo "========================================================"
    echo ""
    $MYSQL_CMD -t -e "SELECT * FROM mysql.db WHERE Db NOT IN ('mysql', 'performance_schema', 'information_schema', 'sys');"
    echo ""

    # Table-level privileges
    echo "--- TABLE-LEVEL PRIVILEGES ---"
    $MYSQL_CMD -t -e "SELECT * FROM mysql.tables_priv LIMIT 50;"
    echo ""

    # Check for UDFs (User Defined Functions) - potential backdoors
    echo "========================================================"
    echo "USER DEFINED FUNCTIONS (potential backdoors)"
    echo "========================================================"
    $MYSQL_CMD -t -e "SELECT * FROM mysql.func;"
    echo ""

    # Check for suspicious stored procedures
    echo "--- STORED PROCEDURES ---"
    $MYSQL_CMD -t -e "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, DEFINER FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('mysql', 'sys', 'performance_schema');"
    echo ""

    # Check for triggers
    echo "--- TRIGGERS (potential backdoors) ---"
    $MYSQL_CMD -t -e "SELECT TRIGGER_SCHEMA, TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA NOT IN ('mysql', 'sys', 'performance_schema');"
    echo ""

    # Recent connections
    echo "========================================================"
    echo "RECENT ACTIVITY"
    echo "========================================================"
    echo ""
    echo "--- CURRENT PROCESSES ---"
    $MYSQL_CMD -t -e "SHOW FULL PROCESSLIST;"
    echo ""

    echo "Audit complete."
    echo "========================================================"

} > "$OUTPUT_FILE" 2>&1

log "Audit complete. Report saved to: $OUTPUT_FILE"

# Print summary to console
echo ""
echo "========================================"
echo "MYSQL AUDIT SUMMARY"
echo "========================================"

# Quick security checks with console output
echo ""
echo "Quick Security Checks:"
echo "----------------------"

# Check for anonymous users
anon_count=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" 2>/dev/null)
if [[ "$anon_count" -gt 0 ]]; then
    critical "Anonymous users found: $anon_count"
else
    log "No anonymous users"
fi

# Check for wildcard hosts
wildcard_count=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM mysql.user WHERE Host='%';" 2>/dev/null)
if [[ "$wildcard_count" -gt 0 ]]; then
    warn "Users with wildcard host (%): $wildcard_count"
fi

# Check for users with no password
nopass_count=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;" 2>/dev/null || echo "0")
if [[ "$nopass_count" -gt 0 ]]; then
    critical "Users with no password: $nopass_count"
fi

# Check local_infile
local_infile=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'local_infile';" 2>/dev/null | awk '{print $2}')
if [[ "$local_infile" == "ON" ]]; then
    warn "local_infile is ON (potential security risk)"
fi

# Check for UDFs
udf_count=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM mysql.func;" 2>/dev/null)
if [[ "$udf_count" -gt 0 ]]; then
    warn "User Defined Functions found: $udf_count (check for backdoors)"
fi

echo ""
echo "Full report: $OUTPUT_FILE"
echo "========================================"

exit 0
