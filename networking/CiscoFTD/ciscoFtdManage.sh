#!/bin/bash
# ==============================================================================
# Script Name: ciscoFtdManage.sh
# Description: Cisco FTD (Firepower Threat Defense) management via SSH/CLI
#              Supports backup, status, and basic configuration operations
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./ciscoFtdManage.sh [options] <action>
#
# Actions:
#   status       Show system info and interface status
#   backup       Backup running configuration to file
#   restore      Push configuration commands from file
#   passwd       Change admin password (interactive)
#   interfaces   Show interface configuration
#   routes       Show routing table
#   sessions     Show active sessions/connections
#
# Options:
#   -h, --help          Show this help message
#   -H, --host HOST     FTD management IP (required)
#   -u, --user USER     SSH username (default: admin)
#   -p, --pass PASS     SSH password (or use FTD_PASS env var)
#   -k, --key FILE      SSH private key file
#   -P, --port PORT     SSH port (default: 22)
#   -o, --output DIR    Output directory for backups
#   -f, --file FILE     Command file for restore
#   --timeout SEC       Command timeout (default: 30)
#   --dry-run           Show what would be done
#
# Environment Variables:
#   FTD_HOST    - FTD management IP
#   FTD_USER    - SSH username
#   FTD_PASS    - SSH password
#
# Prerequisites:
#   - ssh client
#   - expect (for password authentication)
#   - sshpass (alternative to expect)
#
# Notes:
#   - FTD CLI has limited configuration capability compared to FMC
#   - Some commands require 'expert' mode
#   - Configuration changes require deployment from FMC in managed mode
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
HOST="${FTD_HOST:-}"
USER="${FTD_USER:-admin}"
PASS="${FTD_PASS:-}"
SSH_KEY=""
SSH_PORT=22
OUTPUT_DIR="./ftd_backups"
RESTORE_FILE=""
TIMEOUT=30
DRY_RUN=false
ACTION=""

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

# Check for required tools
check_dependencies() {
    if ! command -v ssh &>/dev/null; then
        error "ssh client not found"
        exit 1
    fi

    if [[ -z "$SSH_KEY" && -n "$PASS" ]]; then
        if ! command -v expect &>/dev/null && ! command -v sshpass &>/dev/null; then
            error "expect or sshpass required for password authentication"
            echo "Install with: apt install expect  OR  apt install sshpass"
            exit 1
        fi
    fi
}

# Execute SSH command with password via expect
ssh_expect() {
    local cmd="$1"

    expect -c "
        set timeout $TIMEOUT
        spawn ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -p $SSH_PORT $USER@$HOST
        expect {
            -re \"(?i)password:\" { send \"$PASS\r\"; exp_continue }
            -re \">|#\" {}
            timeout { exit 1 }
        }
        send \"$cmd\r\"
        expect {
            -re \">|#\" {}
            timeout { exit 1 }
        }
        send \"exit\r\"
        expect eof
    " 2>/dev/null | grep -v "^spawn" | grep -v "^$USER@" | tail -n +2 | head -n -1
}

# Execute SSH command with sshpass
ssh_sshpass() {
    local cmd="$1"
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile=/dev/null \
        -p "$SSH_PORT" "$USER@$HOST" "$cmd" 2>/dev/null
}

# Execute SSH command with key
ssh_key() {
    local cmd="$1"
    ssh -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -i "$SSH_KEY" \
        -p "$SSH_PORT" "$USER@$HOST" "$cmd" 2>/dev/null
}

# Execute SSH command (auto-select method)
ssh_cmd() {
    local cmd="$1"

    if [[ -n "$SSH_KEY" ]]; then
        ssh_key "$cmd"
    elif command -v sshpass &>/dev/null; then
        ssh_sshpass "$cmd"
    else
        ssh_expect "$cmd"
    fi
}

# Execute multiple commands via expect (for interactive sessions)
ssh_multi_cmd() {
    local cmds="$1"

    if [[ -n "$SSH_KEY" ]]; then
        ssh -o StrictHostKeyChecking=accept-new \
            -o UserKnownHostsFile=/dev/null \
            -o BatchMode=yes \
            -i "$SSH_KEY" \
            -p "$SSH_PORT" "$USER@$HOST" <<< "$cmds"
    else
        expect -c "
            set timeout $TIMEOUT
            spawn ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -p $SSH_PORT $USER@$HOST
            expect {
                -re \"(?i)password:\" { send \"$PASS\r\"; exp_continue }
                -re \">|#\" {}
                timeout { exit 1 }
            }
            foreach line [split {$cmds} \"\n\"] {
                send \"\$line\r\"
                expect {
                    -re \">|#\" {}
                    timeout { break }
                }
            }
            send \"exit\r\"
            expect eof
        " 2>/dev/null
    fi
}

# --- Actions ---

# Show system status
do_status() {
    log "Fetching system information..."

    echo ""
    echo "========================================"
    echo "CISCO FTD SYSTEM STATUS"
    echo "========================================"
    echo ""

    # Get version info
    log "Getting version..."
    echo "--- Version ---"
    ssh_cmd "show version" | head -20
    echo ""

    # Get hostname
    log "Getting hostname..."
    echo "--- Hostname ---"
    ssh_cmd "show hostname"
    echo ""

    # Get managers (FMC connection)
    log "Getting manager status..."
    echo "--- Manager Status ---"
    ssh_cmd "show managers"
    echo ""

    # Get uptime
    log "Getting uptime..."
    echo "--- Uptime ---"
    ssh_cmd "show uptime"
    echo ""
}

# Show interfaces
do_interfaces() {
    log "Fetching interface information..."

    echo ""
    echo "========================================"
    echo "INTERFACE STATUS"
    echo "========================================"
    echo ""

    ssh_cmd "show interface ip brief"
    echo ""

    log "Interface details..."
    ssh_cmd "show interface"
}

# Show routes
do_routes() {
    log "Fetching routing table..."

    echo ""
    echo "========================================"
    echo "ROUTING TABLE"
    echo "========================================"
    echo ""

    ssh_cmd "show route"
}

# Show active sessions
do_sessions() {
    log "Fetching session information..."

    echo ""
    echo "========================================"
    echo "ACTIVE SESSIONS"
    echo "========================================"
    echo ""

    # Connection count
    echo "--- Connection Summary ---"
    ssh_cmd "show conn count"
    echo ""

    # Top connections
    echo "--- Recent Connections (sample) ---"
    ssh_cmd "show conn" | head -50
}

# Backup configuration
do_backup() {
    log "Backing up configuration..."

    mkdir -p "$OUTPUT_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${OUTPUT_DIR}/ftd_${HOST}_${timestamp}.txt"

    echo "# Cisco FTD Configuration Backup" > "$backup_file"
    echo "# Host: $HOST" >> "$backup_file"
    echo "# Date: $(date)" >> "$backup_file"
    echo "# ======================================" >> "$backup_file"
    echo "" >> "$backup_file"

    # Get running configuration
    log "Exporting running configuration..."
    echo "# --- Running Configuration ---" >> "$backup_file"
    ssh_cmd "show running-config" >> "$backup_file"
    echo "" >> "$backup_file"

    # Get access lists
    log "Exporting access lists..."
    echo "# --- Access Lists ---" >> "$backup_file"
    ssh_cmd "show access-list" >> "$backup_file"
    echo "" >> "$backup_file"

    # Get NAT rules
    log "Exporting NAT rules..."
    echo "# --- NAT Rules ---" >> "$backup_file"
    ssh_cmd "show nat" >> "$backup_file"
    echo "" >> "$backup_file"

    # Get interface config
    log "Exporting interface config..."
    echo "# --- Interfaces ---" >> "$backup_file"
    ssh_cmd "show interface ip brief" >> "$backup_file"
    echo "" >> "$backup_file"

    # Get routes
    log "Exporting routes..."
    echo "# --- Routes ---" >> "$backup_file"
    ssh_cmd "show route" >> "$backup_file"

    chmod 600 "$backup_file"

    log "Configuration backed up to: $backup_file"
    echo "Backup size: $(du -h "$backup_file" | cut -f1)"
}

# Restore/push configuration commands
do_restore() {
    if [[ -z "$RESTORE_FILE" ]]; then
        error "Restore file required (use -f option)"
        exit 1
    fi

    if [[ ! -f "$RESTORE_FILE" ]]; then
        error "Restore file not found: $RESTORE_FILE"
        exit 1
    fi

    warn "FTD configuration restoration notes:"
    echo "  - In FMC-managed mode, most config comes from FMC"
    echo "  - This will attempt to push CLI commands directly"
    echo "  - Some commands may fail or require 'configure' mode"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Would push commands from: $RESTORE_FILE"
        echo ""
        echo "Commands to push:"
        grep -v "^#" "$RESTORE_FILE" | grep -v "^$" | head -20
        return 0
    fi

    read -rp "Continue with restore? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log "Restore cancelled"
        return 0
    fi

    log "Pushing configuration commands..."

    # Read commands from file (skip comments and empty lines)
    local cmds
    cmds=$(grep -v "^#" "$RESTORE_FILE" | grep -v "^$")

    # Enter configure mode and push commands
    local full_cmds="configure terminal
$cmds
end
write memory"

    ssh_multi_cmd "$full_cmds"

    log "Configuration commands pushed"
    warn "Verify changes with: $0 -H $HOST status"
}

# Change password
do_passwd() {
    log "Changing password..."

    echo "This will change the password for user: $USER"
    echo ""
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
        log "[DRY-RUN] Would change password for $USER"
        return 0
    fi

    # Change password via configure mode
    local cmds="configure user $USER password"

    warn "You may need to enter the new password interactively"

    ssh_multi_cmd "$cmds"

    log "Password change command sent"
    warn "Test login with new password before closing this session"
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
            SSH_KEY="$2"
            shift 2
            ;;
        -P|--port)
            SSH_PORT="$2"
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
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        status|backup|restore|passwd|interfaces|routes|sessions)
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
    error "Host required (use -H or FTD_HOST env var)"
    exit 1
fi

if [[ -z "$SSH_KEY" && -z "$PASS" ]]; then
    error "Password or SSH key required"
    exit 1
fi

# --- Main ---
echo "========================================"
echo "Cisco FTD Management Tool"
echo "Host: $HOST"
echo "User: $USER"
echo "Time: $(date)"
echo "========================================"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    warn "DRY-RUN MODE - No changes will be made"
    echo ""
fi

check_dependencies

# Test connectivity
log "Testing SSH connectivity..."
if ! ssh_cmd "show hostname" &>/dev/null; then
    error "Failed to connect to $HOST"
    exit 2
fi
log "Connection successful"
echo ""

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
    passwd)
        do_passwd
        ;;
    interfaces)
        do_interfaces
        ;;
    routes)
        do_routes
        ;;
    sessions)
        do_sessions
        ;;
esac

exit 0
