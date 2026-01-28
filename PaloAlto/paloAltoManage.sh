#!/bin/bash
# ==============================================================================
# Script Name: paloAltoManage.sh
# Description: Palo Alto firewall management via REST API
#              Supports backup, restore, harden, and status operations
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./paloAltoManage.sh [options] <action>
#
# Actions:
#   status       Show system info and interface status
#   backup       Backup running configuration to file
#   restore      Restore configuration from backup file
#   harden       Apply security hardening settings
#   passwd       Change admin password
#
# Options:
#   -h, --help          Show this help message
#   -H, --host HOST     Palo Alto management IP (required)
#   -u, --user USER     API username (default: admin)
#   -p, --pass PASS     API password (or use PA_PASS env var)
#   -k, --key KEY       API key (alternative to user/pass)
#   -o, --output DIR    Output directory for backups
#   -f, --file FILE     Config file for restore
#   -i, --insecure      Skip TLS certificate verification
#   --mgmt-ips IPS      Comma-separated management IPs for hardening
#   --dry-run           Show what would be done without making changes
#
# Environment Variables:
#   PA_HOST     - Palo Alto management IP
#   PA_USER     - API username
#   PA_PASS     - API password
#   PA_KEY      - API key
#
# Prerequisites:
#   - curl
#   - xmllint (libxml2-utils)
#   - jq (optional, for JSON parsing)
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - Connection failed
#   3 - Authentication failed
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
HOST="${PA_HOST:-}"
USER="${PA_USER:-admin}"
PASS="${PA_PASS:-}"
API_KEY="${PA_KEY:-}"
OUTPUT_DIR="./pa_backups"
RESTORE_FILE=""
MGMT_IPS=""
INSECURE=true
DRY_RUN=false
ACTION=""

# API endpoints
API_BASE=""

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -55 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
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

debug() {
    [[ "${DEBUG:-false}" == "true" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Curl wrapper with common options
api_call() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    local curl_opts="-s --max-time 30"

    [[ "$INSECURE" == "true" ]] && curl_opts="$curl_opts -k"

    if [[ -n "$data" ]]; then
        curl $curl_opts -X "$method" -d "$data" "$endpoint"
    else
        curl $curl_opts -X "$method" "$endpoint"
    fi
}

# Get API key from username/password
get_api_key() {
    if [[ -n "$API_KEY" ]]; then
        return 0
    fi

    if [[ -z "$PASS" ]]; then
        error "Password required (use -p or PA_PASS env var)"
        exit 3
    fi

    log "Obtaining API key..."
    local response
    response=$(api_call "https://${HOST}/api/?type=keygen&user=${USER}&password=${PASS}")

    # Extract key from XML response
    API_KEY=$(echo "$response" | grep -oP '(?<=<key>)[^<]+' || true)

    if [[ -z "$API_KEY" ]]; then
        # Check for error message
        local errmsg
        errmsg=$(echo "$response" | grep -oP '(?<=<msg>)[^<]+' || echo "Unknown error")
        error "Failed to get API key: $errmsg"
        exit 3
    fi

    debug "API key obtained successfully"
}

# Make API operation call
api_op() {
    local cmd="$1"
    api_call "https://${HOST}/api/?type=op&cmd=${cmd}&key=${API_KEY}"
}

# Make API config call
api_config() {
    local action="$1"
    local xpath="$2"
    local element="${3:-}"

    local url="https://${HOST}/api/?type=config&action=${action}&xpath=${xpath}&key=${API_KEY}"
    if [[ -n "$element" ]]; then
        url="${url}&element=${element}"
    fi

    api_call "$url"
}

# Commit changes
api_commit() {
    log "Committing configuration..."
    local response
    response=$(api_call "https://${HOST}/api/?type=commit&cmd=<commit></commit>&key=${API_KEY}")

    if echo "$response" | grep -q "success"; then
        log "Commit successful"
        return 0
    else
        local errmsg
        errmsg=$(echo "$response" | grep -oP '(?<=<msg>)[^<]+' || echo "Unknown error")
        error "Commit failed: $errmsg"
        return 1
    fi
}

# --- Actions ---

# Show system status
do_status() {
    log "Fetching system information..."

    # Get system info
    local sysinfo
    sysinfo=$(api_op "<show><system><info></info></system></show>")

    echo ""
    echo "========================================"
    echo "PALO ALTO SYSTEM STATUS"
    echo "========================================"
    echo ""

    # Parse and display key fields
    local hostname model serial swver uptime
    hostname=$(echo "$sysinfo" | grep -oP '(?<=<hostname>)[^<]+' || echo "N/A")
    model=$(echo "$sysinfo" | grep -oP '(?<=<model>)[^<]+' || echo "N/A")
    serial=$(echo "$sysinfo" | grep -oP '(?<=<serial>)[^<]+' || echo "N/A")
    swver=$(echo "$sysinfo" | grep -oP '(?<=<sw-version>)[^<]+' || echo "N/A")
    uptime=$(echo "$sysinfo" | grep -oP '(?<=<uptime>)[^<]+' || echo "N/A")
    mgmt_ip=$(echo "$sysinfo" | grep -oP '(?<=<ip-address>)[^<]+' || echo "N/A")

    echo "Hostname:     $hostname"
    echo "Model:        $model"
    echo "Serial:       $serial"
    echo "SW Version:   $swver"
    echo "Mgmt IP:      $mgmt_ip"
    echo "Uptime:       $uptime"
    echo ""

    # Get interface status
    log "Fetching interface status..."
    local interfaces
    interfaces=$(api_op "<show><interface>all</interface></show>")

    echo "Interfaces:"
    echo "$interfaces" | grep -oP '(?<=<name>)[^<]+' | head -10 | while read -r iface; do
        echo "  - $iface"
    done
    echo ""

    # Get active sessions count
    log "Fetching session count..."
    local sessions
    sessions=$(api_op "<show><session><info></info></session></show>")
    local sess_count
    sess_count=$(echo "$sessions" | grep -oP '(?<=<num-active>)[^<]+' || echo "N/A")
    echo "Active Sessions: $sess_count"
}

# Backup configuration
do_backup() {
    log "Backing up configuration..."

    mkdir -p "$OUTPUT_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${OUTPUT_DIR}/paloalto_${HOST}_${timestamp}.xml"

    # Export running config
    local config
    config=$(api_call "https://${HOST}/api/?type=export&category=configuration&key=${API_KEY}")

    if [[ -z "$config" ]] || echo "$config" | grep -q "<response.*error"; then
        error "Failed to export configuration"
        return 1
    fi

    echo "$config" > "$backup_file"
    chmod 600 "$backup_file"

    log "Configuration backed up to: $backup_file"
    echo "Backup size: $(du -h "$backup_file" | cut -f1)"
}

# Restore configuration
do_restore() {
    if [[ -z "$RESTORE_FILE" ]]; then
        error "Restore file required (use -f option)"
        exit 1
    fi

    if [[ ! -f "$RESTORE_FILE" ]]; then
        error "Restore file not found: $RESTORE_FILE"
        exit 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Would restore configuration from: $RESTORE_FILE"
        return 0
    fi

    log "Uploading configuration..."

    # Import configuration
    local response
    response=$(curl -sk -F "file=@${RESTORE_FILE}" \
        "https://${HOST}/api/?type=import&category=configuration&key=${API_KEY}")

    if ! echo "$response" | grep -q "success"; then
        error "Failed to import configuration"
        echo "$response"
        return 1
    fi

    # Get the imported filename
    local imported_name
    imported_name=$(echo "$response" | grep -oP '(?<=<msg>)[^<]+' | grep -oP '[^ ]+$' || basename "$RESTORE_FILE")

    log "Loading configuration: $imported_name"

    # Load the imported configuration
    response=$(api_op "<load><config><from>${imported_name}</from></config></load>")

    if ! echo "$response" | grep -q "success"; then
        error "Failed to load configuration"
        return 1
    fi

    # Commit
    api_commit

    log "Configuration restored successfully"
}

# Apply hardening settings
do_harden() {
    log "Applying security hardening..."

    if [[ -z "$MGMT_IPS" ]]; then
        warn "No management IPs specified (use --mgmt-ips)"
        warn "Skipping management IP restriction"
    fi

    local xpath_base="/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would apply the following settings:"
        echo "  - Disable HTTP management interface"
        echo "  - Disable Telnet management interface"
        [[ -n "$MGMT_IPS" ]] && echo "  - Restrict management to: $MGMT_IPS"
        return 0
    fi

    # Backup first
    log "Creating backup before hardening..."
    do_backup

    # Disable HTTP management
    log "Disabling HTTP management..."
    api_config "set" "${xpath_base}/service" "<disable-http>yes</disable-http>"

    # Disable Telnet management
    log "Disabling Telnet management..."
    api_config "set" "${xpath_base}/service" "<disable-telnet>yes</disable-telnet>"

    # Restrict management IPs
    if [[ -n "$MGMT_IPS" ]]; then
        log "Restricting management to: $MGMT_IPS"
        local members=""
        IFS=',' read -ra IPS <<< "$MGMT_IPS"
        for ip in "${IPS[@]}"; do
            ip=$(echo "$ip" | xargs)  # Trim whitespace
            members="${members}<member>${ip}</member>"
        done
        api_config "edit" "${xpath_base}/permitted-ip" "$members"
    fi

    # Commit changes
    api_commit

    log "Hardening complete"
    echo ""
    echo "Applied settings:"
    echo "  - HTTP management: Disabled"
    echo "  - Telnet management: Disabled"
    [[ -n "$MGMT_IPS" ]] && echo "  - Management IPs: $MGMT_IPS"
}

# Change admin password
do_passwd() {
    log "Changing admin password..."

    echo -n "Enter new password: "
    read -rs new_pass
    echo ""
    echo -n "Confirm new password: "
    read -rs confirm_pass
    echo ""

    if [[ "$new_pass" != "$confirm_pass" ]]; then
        error "Passwords do not match"
        return 1
    fi

    if [[ ${#new_pass} -lt 8 ]]; then
        error "Password must be at least 8 characters"
        return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Would change admin password"
        return 0
    fi

    # Hash the password (Palo Alto expects phash)
    local xpath="/config/mgt-config/users/entry[@name='admin']/phash"

    # Use the API to set the password
    local response
    response=$(api_call "https://${HOST}/api/?type=op&cmd=<request><password-hash><password>${new_pass}</password></password-hash></request>&key=${API_KEY}")

    local phash
    phash=$(echo "$response" | grep -oP '(?<=<phash>)[^<]+' || true)

    if [[ -z "$phash" ]]; then
        error "Failed to generate password hash"
        return 1
    fi

    # Set the new password hash
    api_config "edit" "$xpath" "<phash>${phash}</phash>"

    # Commit
    api_commit

    log "Password changed successfully"
    warn "You will need to use the new password for future API calls"
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -H|--host)
            HOST="$2"
            shift 2
            ;;
        -u|--user)
            USER="$2"
            shift 2
            ;;
        -p|--pass)
            PASS="$2"
            shift 2
            ;;
        -k|--key)
            API_KEY="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--file)
            RESTORE_FILE="$2"
            shift 2
            ;;
        -i|--insecure)
            INSECURE=true
            shift
            ;;
        --mgmt-ips)
            MGMT_IPS="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        status|backup|restore|harden|passwd)
            ACTION="$1"
            shift
            ;;
        *)
            error "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Validation ---
if [[ -z "$ACTION" ]]; then
    error "No action specified"
    usage
fi

if [[ -z "$HOST" ]]; then
    error "Host required (use -H or PA_HOST env var)"
    exit 1
fi

API_BASE="https://${HOST}/api/"

# --- Main ---
echo "========================================"
echo "Palo Alto Management Tool"
echo "Host: $HOST"
echo "Time: $(date)"
echo "========================================"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    warn "DRY-RUN MODE - No changes will be made"
    echo ""
fi

# Get API key if needed
get_api_key

# Execute action
case "$ACTION" in
    status)
        do_status
        ;;
    backup)
        do_backup
        ;;
    restore)
        do_restore
        ;;
    harden)
        do_harden
        ;;
    passwd)
        do_passwd
        ;;
esac

exit 0
