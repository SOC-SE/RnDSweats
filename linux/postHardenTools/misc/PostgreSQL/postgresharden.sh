#!/bin/bash
# ==============================================================================
# Script Name: postgresharden.sh
# Description: PostgreSQL hardening script - restricts authentication, enables
#              SSL, logging, revokes PUBLIC access, manages superusers
# Author: Security Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./postgresharden.sh [options]
#
# Options:
#   -h, --help           Show this help message
#   -U, --user           PostgreSQL username (default: postgres)
#   -W, --password       PostgreSQL password (will prompt if not set)
#   -H, --host           PostgreSQL host (default: localhost)
#   -p, --port           PostgreSQL port (default: 5432)
#   -r, --allow-remote   Skip binding to localhost
#
# Prerequisites:
#   - psql client installed
#   - Access to PostgreSQL server
#   - Root/sudo access for config file changes
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
ALLOW_REMOTE=false

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

echo ""
echo "========================================"
echo "POSTGRESQL HARDENING"
echo "========================================"
echo ""

# --- Find config files ---
PG_DATA=$($PSQL_CMD -t -c "SHOW data_directory;" 2>/dev/null | tr -d '[:space:]')
PG_HBA=$($PSQL_CMD -t -c "SHOW hba_file;" 2>/dev/null | tr -d '[:space:]')
PG_CONF=$($PSQL_CMD -t -c "SHOW config_file;" 2>/dev/null | tr -d '[:space:]')

if [[ -z "$PG_DATA" || -z "$PG_HBA" || -z "$PG_CONF" ]]; then
    error "Could not determine PostgreSQL config paths"
    exit 1
fi

log "Data directory: $PG_DATA"
log "pg_hba.conf: $PG_HBA"
log "postgresql.conf: $PG_CONF"

# --- 1 & 8. Restrict pg_hba.conf - replace trust/ident with scram-sha-256 ---
if [[ -f "$PG_HBA" ]]; then
    log "Hardening pg_hba.conf..."
    cp "$PG_HBA" "${PG_HBA}.bak.$(date +%Y%m%d%H%M%S)"
    log "pg_hba.conf backed up"

    # Replace trust and ident with scram-sha-256 (skip comments and replication lines)
    sed -i '/^[[:space:]]*#/!s/\btrust\b/scram-sha-256/g' "$PG_HBA"
    sed -i '/^[[:space:]]*#/!s/\bident\b/scram-sha-256/g' "$PG_HBA"

    log "Replaced trust/ident with scram-sha-256 in pg_hba.conf"
else
    warn "pg_hba.conf not found at $PG_HBA"
fi

# --- 2. Set listen_addresses ---
if [[ -f "$PG_CONF" ]]; then
    log "Hardening postgresql.conf..."
    cp "$PG_CONF" "${PG_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    log "postgresql.conf backed up"

    if [[ "$ALLOW_REMOTE" == "false" ]]; then
        if grep -q "^listen_addresses" "$PG_CONF" 2>/dev/null; then
            sed -i "s/^listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF"
        elif grep -q "^#listen_addresses" "$PG_CONF" 2>/dev/null; then
            sed -i "s/^#listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF"
        else
            echo "listen_addresses = 'localhost'" >> "$PG_CONF"
        fi
        log "listen_addresses set to localhost"
    else
        warn "Skipping listen_addresses (--allow-remote specified)"
    fi

    # --- 3. Enable SSL if certs exist ---
    SSL_CERT="$PG_DATA/server.crt"
    SSL_KEY="$PG_DATA/server.key"
    if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
        if grep -q "^ssl " "$PG_CONF" 2>/dev/null; then
            sed -i "s/^ssl .*/ssl = on/" "$PG_CONF"
        elif grep -q "^#ssl " "$PG_CONF" 2>/dev/null; then
            sed -i "s/^#ssl .*/ssl = on/" "$PG_CONF"
        else
            echo "ssl = on" >> "$PG_CONF"
        fi
        log "SSL enabled (certs found)"
    else
        warn "SSL certs not found at $PG_DATA - skipping SSL"
    fi

    # --- 4. Enable connection logging ---
    for param in "log_connections = on" "log_disconnections = on" "log_statement = 'ddl'"; do
        param_name=$(echo "$param" | cut -d'=' -f1 | tr -d '[:space:]')
        if grep -q "^${param_name}" "$PG_CONF" 2>/dev/null; then
            sed -i "s/^${param_name}.*/${param}/" "$PG_CONF"
        elif grep -q "^#${param_name}" "$PG_CONF" 2>/dev/null; then
            sed -i "s/^#${param_name}.*/${param}/" "$PG_CONF"
        else
            echo "$param" >> "$PG_CONF"
        fi
    done
    log "Connection logging enabled (log_connections, log_disconnections, log_statement=ddl)"

    # --- 5. Set password encryption to scram-sha-256 ---
    if grep -q "^password_encryption" "$PG_CONF" 2>/dev/null; then
        sed -i "s/^password_encryption.*/password_encryption = 'scram-sha-256'/" "$PG_CONF"
    elif grep -q "^#password_encryption" "$PG_CONF" 2>/dev/null; then
        sed -i "s/^#password_encryption.*/password_encryption = 'scram-sha-256'/" "$PG_CONF"
    else
        echo "password_encryption = 'scram-sha-256'" >> "$PG_CONF"
    fi
    log "Password encryption set to scram-sha-256"
else
    warn "postgresql.conf not found at $PG_CONF"
fi

# --- 6. Revoke PUBLIC from default databases ---
log "Revoking PUBLIC privileges from template databases..."
if $PSQL_CMD -c "REVOKE ALL ON DATABASE template1 FROM PUBLIC;" 2>/dev/null; then
    log "Revoked PUBLIC from template1"
else
    warn "Could not revoke PUBLIC from template1"
fi

if $PSQL_CMD -c "REVOKE ALL ON DATABASE template0 FROM PUBLIC;" 2>/dev/null; then
    log "Revoked PUBLIC from template0"
else
    warn "Could not revoke PUBLIC from template0"
fi

# Also revoke from postgres database
if $PSQL_CMD -c "REVOKE ALL ON DATABASE postgres FROM PUBLIC;" 2>/dev/null; then
    log "Revoked PUBLIC from postgres database"
else
    warn "Could not revoke PUBLIC from postgres"
fi

# --- 7. Check for extra superusers ---
log "Checking for extra superusers..."
extra_supers=$($PSQL_CMD -t -c "SELECT rolname FROM pg_roles WHERE rolsuper = true AND rolname != 'postgres';" 2>/dev/null | tr -d '[:space:]')

if [[ -n "$extra_supers" ]]; then
    warn "Extra superusers found (besides postgres):"
    $PSQL_CMD -t -c "SELECT rolname FROM pg_roles WHERE rolsuper = true AND rolname != 'postgres';" 2>/dev/null | while IFS= read -r role; do
        role=$(echo "$role" | tr -d '[:space:]')
        [[ -z "$role" ]] && continue
        echo -e "  ${YELLOW}→${NC} $role"
        read -rp "  Revoke superuser from '$role'? (y/N): " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            if $PSQL_CMD -c "ALTER ROLE \"$role\" NOSUPERUSER;" 2>/dev/null; then
                log "Revoked superuser from $role"
            else
                warn "Failed to revoke superuser from $role"
            fi
        else
            warn "Keeping superuser for $role"
        fi
    done
else
    log "No extra superusers found"
fi

# --- 9. Reload config ---
log "Reloading PostgreSQL configuration..."
if $PSQL_CMD -c "SELECT pg_reload_conf();" &>/dev/null; then
    log "Configuration reloaded"
else
    warn "Could not reload config - restart PostgreSQL manually"
fi

echo ""
echo "========================================"
echo "POSTGRESQL HARDENING COMPLETE"
echo "========================================"
echo ""
warn "Some changes (listen_addresses, SSL) require a full restart: systemctl restart postgresql"

exit 0
