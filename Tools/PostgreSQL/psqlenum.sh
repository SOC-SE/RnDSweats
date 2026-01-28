#!/bin/bash
# ==============================================================================
# Script Name: psqlenum.sh
# Description: PostgreSQL security audit script - enumerates databases, users,
#              privileges, and potential security issues
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./psqlenum.sh [options]
#
# Options:
#   -h, --help           Show this help message
#   -U, --user           PostgreSQL username (default: postgres)
#   -W, --password       PostgreSQL password (will prompt if not set)
#   -H, --host           PostgreSQL host (default: localhost)
#   -p, --port           PostgreSQL port (default: 5432)
#   -o, --output         Output file (default: psql_audit_report.txt)
#
# Prerequisites:
#   - psql client installed
#   - Access to PostgreSQL server
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - PostgreSQL connection failed
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
PSQL_USER="postgres"
PSQL_HOST="localhost"
PSQL_PORT="5432"
OUTPUT_FILE="$(dirname "$0")/psql_audit_report.txt"

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
        -U|--user)
            PSQL_USER="$2"
            shift 2
            ;;
        -W|--password)
            export PGPASSWORD="$2"
            shift 2
            ;;
        -H|--host)
            PSQL_HOST="$2"
            shift 2
            ;;
        -p|--port)
            PSQL_PORT="$2"
            shift 2
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

# --- Build psql command ---
PSQL_CMD="psql -h $PSQL_HOST -p $PSQL_PORT -U $PSQL_USER"

# --- Test connection ---
log "Testing PostgreSQL connection to $PSQL_HOST:$PSQL_PORT..."
if ! $PSQL_CMD -c "SELECT 1" &>/dev/null; then
    error "Failed to connect to PostgreSQL"
    error "Hint: Set PGPASSWORD environment variable or use -W option"
    exit 2
fi
log "Connection successful"

# --- Main Audit ---
{
    echo "========================================================"
    echo "POSTGRESQL SECURITY AUDIT REPORT"
    echo "Host: $PSQL_HOST:$PSQL_PORT"
    echo "User: $PSQL_USER"
    echo "Date: $(date)"
    echo "========================================================"
    echo ""

    # Server version
    echo "--- SERVER INFORMATION ---"
    $PSQL_CMD -c "SELECT version();"
    echo ""

    # List databases
    echo "--- DATABASES ---"
    $PSQL_CMD -c "SELECT datname, datdba::regrole, encoding, datcollate, datctype FROM pg_database WHERE datistemplate = false;"
    echo ""

    # List all roles/users
    echo "--- ALL ROLES/USERS ---"
    $PSQL_CMD -c "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, rolvaliduntil FROM pg_roles ORDER BY rolname;"
    echo ""

    # Superusers
    echo "--- SUPERUSERS ---"
    $PSQL_CMD -c "SELECT rolname FROM pg_roles WHERE rolsuper = true;"
    echo ""

    # Users who can create databases
    echo "--- USERS WITH CREATEDB ---"
    $PSQL_CMD -c "SELECT rolname FROM pg_roles WHERE rolcreatedb = true;"
    echo ""

    # Users who can create roles
    echo "--- USERS WITH CREATEROLE ---"
    $PSQL_CMD -c "SELECT rolname FROM pg_roles WHERE rolcreaterole = true;"
    echo ""

    # Users with replication privilege
    echo "--- USERS WITH REPLICATION ---"
    $PSQL_CMD -c "SELECT rolname FROM pg_roles WHERE rolreplication = true;"
    echo ""

    # Users with no password expiry
    echo "--- USERS WITH NO PASSWORD EXPIRY ---"
    $PSQL_CMD -c "SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolvaliduntil IS NULL AND rolcanlogin = true;"
    echo ""

    # Role memberships
    echo "--- ROLE MEMBERSHIPS ---"
    $PSQL_CMD -c "SELECT r.rolname AS role, m.rolname AS member, g.rolname AS grantor FROM pg_auth_members am JOIN pg_roles r ON am.roleid = r.oid JOIN pg_roles m ON am.member = m.oid JOIN pg_roles g ON am.grantor = g.oid ORDER BY r.rolname, m.rolname;"
    echo ""

    # Database privileges
    echo "========================================================"
    echo "DATABASE PRIVILEGES"
    echo "========================================================"

    # Get list of non-template databases
    databases=$($PSQL_CMD -t -c "SELECT datname FROM pg_database WHERE datistemplate = false;")

    for db in $databases; do
        db=$(echo "$db" | tr -d '[:space:]')
        [[ -z "$db" ]] && continue

        echo ""
        echo "=========================================="
        echo "Database: $db"
        echo "=========================================="

        # Table privileges
        echo ""
        echo "--- TABLE PRIVILEGES ---"
        $PSQL_CMD -d "$db" -c "
            SELECT grantor, grantee, table_schema, table_name, privilege_type, is_grantable
            FROM information_schema.role_table_grants
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name, grantee;" 2>/dev/null || echo "(Unable to query)"

        # Schema privileges
        echo ""
        echo "--- SCHEMA PRIVILEGES ---"
        $PSQL_CMD -d "$db" -c "
            SELECT nspname AS schema,
                   pg_catalog.pg_get_userbyid(nspowner) AS owner,
                   nspacl AS privileges
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT LIKE 'pg_%' AND nspname != 'information_schema';" 2>/dev/null || echo "(Unable to query)"

        # Function privileges (potential backdoors)
        echo ""
        echo "--- FUNCTIONS (potential backdoors) ---"
        $PSQL_CMD -d "$db" -c "
            SELECT n.nspname AS schema,
                   p.proname AS function_name,
                   pg_catalog.pg_get_userbyid(p.proowner) AS owner,
                   l.lanname AS language
            FROM pg_catalog.pg_proc p
            LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY n.nspname, p.proname;" 2>/dev/null || echo "(Unable to query)"

        # Triggers (potential backdoors)
        echo ""
        echo "--- TRIGGERS (potential backdoors) ---"
        $PSQL_CMD -d "$db" -c "
            SELECT trigger_schema, trigger_name, event_manipulation,
                   event_object_table, action_statement
            FROM information_schema.triggers
            WHERE trigger_schema NOT IN ('pg_catalog', 'information_schema');" 2>/dev/null || echo "(Unable to query)"

        # Extensions
        echo ""
        echo "--- INSTALLED EXTENSIONS ---"
        $PSQL_CMD -d "$db" -c "SELECT extname, extversion FROM pg_extension;" 2>/dev/null || echo "(Unable to query)"

    done

    # pg_hba.conf equivalent - authentication settings
    echo ""
    echo "========================================================"
    echo "AUTHENTICATION SETTINGS"
    echo "========================================================"
    $PSQL_CMD -c "SELECT * FROM pg_hba_file_rules;" 2>/dev/null || echo "(pg_hba_file_rules not available - check pg_hba.conf manually)"
    echo ""

    # Configuration settings
    echo "========================================================"
    echo "SECURITY-RELEVANT SETTINGS"
    echo "========================================================"
    $PSQL_CMD -c "
        SELECT name, setting, unit, context
        FROM pg_settings
        WHERE name IN (
            'listen_addresses',
            'port',
            'ssl',
            'ssl_cert_file',
            'ssl_key_file',
            'password_encryption',
            'log_connections',
            'log_disconnections',
            'log_statement',
            'log_min_duration_statement'
        );"
    echo ""

    # Active connections
    echo "========================================================"
    echo "ACTIVE CONNECTIONS"
    echo "========================================================"
    $PSQL_CMD -c "SELECT datname, usename, client_addr, client_port, backend_start, state, query FROM pg_stat_activity WHERE state != 'idle' OR query NOT LIKE '%pg_stat_activity%';"
    echo ""

    echo "Audit complete."
    echo "========================================================"

} > "$OUTPUT_FILE" 2>&1

log "Audit complete. Report saved to: $OUTPUT_FILE"

# Print summary to console
echo ""
echo "========================================"
echo "POSTGRESQL AUDIT SUMMARY"
echo "========================================"

echo ""
echo "Quick Security Checks:"
echo "----------------------"

# Check for superusers
superuser_count=$($PSQL_CMD -t -c "SELECT COUNT(*) FROM pg_roles WHERE rolsuper = true;" 2>/dev/null | tr -d '[:space:]')
if [[ "$superuser_count" -gt 1 ]]; then
    warn "Multiple superusers found: $superuser_count"
else
    log "Superusers: $superuser_count"
fi

# Check for users with no password expiry
no_expiry=$($PSQL_CMD -t -c "SELECT COUNT(*) FROM pg_roles WHERE rolvaliduntil IS NULL AND rolcanlogin = true;" 2>/dev/null | tr -d '[:space:]')
if [[ "$no_expiry" -gt 0 ]]; then
    warn "Users with no password expiry: $no_expiry"
fi

# Check if SSL is enabled
ssl_enabled=$($PSQL_CMD -t -c "SHOW ssl;" 2>/dev/null | tr -d '[:space:]')
if [[ "$ssl_enabled" != "on" ]]; then
    warn "SSL is not enabled"
else
    log "SSL is enabled"
fi

# Check listen_addresses
listen_addr=$($PSQL_CMD -t -c "SHOW listen_addresses;" 2>/dev/null | tr -d '[:space:]')
if [[ "$listen_addr" == "*" ]]; then
    warn "PostgreSQL is listening on all interfaces (*)"
fi

# Check log_connections
log_conn=$($PSQL_CMD -t -c "SHOW log_connections;" 2>/dev/null | tr -d '[:space:]')
if [[ "$log_conn" != "on" ]]; then
    warn "Connection logging is disabled"
fi

# Count databases
db_count=$($PSQL_CMD -t -c "SELECT COUNT(*) FROM pg_database WHERE datistemplate = false;" 2>/dev/null | tr -d '[:space:]')
log "Databases: $db_count"

# Count roles
role_count=$($PSQL_CMD -t -c "SELECT COUNT(*) FROM pg_roles;" 2>/dev/null | tr -d '[:space:]')
log "Roles/Users: $role_count"

echo ""
echo "Full report: $OUTPUT_FILE"
echo "========================================"

exit 0
