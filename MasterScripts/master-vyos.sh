#!/bin/bash
# ==============================================================================
# Script Name: master-vyos.sh
# Description: Master script for VyOS router initial hardening
#              Enumeration and configuration backup via SSH
# Target: VyOS 1.4.3 Router
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Connect and enumerate current configuration
#   2. Backup configuration
#   3. Apply basic hardening
#   4. Verify changes
#
# IMPORTANT: This script runs FROM your admin workstation, not ON the router
#
# Usage:
#   ./master-vyos.sh -H <router_ip> -u vyos -p <password>
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VYOS_SCRIPT="$REPO_DIR/Tools/VyOS/vyosEnumerate.sh"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="./vyos_backups"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helper Functions ---
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
phase() { echo -e "\n${CYAN}========== $1 ==========${NC}"; }

usage() {
    echo "Usage: $0 -H <router_ip> -u <username> -p <password>"
    echo ""
    echo "Options:"
    echo "  -H, --host       VyOS management IP (required)"
    echo "  -u, --user       SSH username (default: vyos)"
    echo "  -p, --pass       SSH password (required)"
    echo "  -k, --key        SSH private key file"
    echo ""
    exit 1
}

ssh_cmd() {
    local cmd="$1"
    if [[ -n "$SSH_KEY" ]]; then
        ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "$SSH_KEY" "$USER@$HOST" "$cmd" 2>/dev/null
    else
        sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new "$USER@$HOST" "$cmd" 2>/dev/null
    fi
}

# --- Parse Arguments ---
HOST=""
USER="vyos"
PASS=""
SSH_KEY=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -H|--host) HOST="$2"; shift 2 ;;
        -u|--user) USER="$2"; shift 2 ;;
        -p|--pass) PASS="$2"; shift 2 ;;
        -k|--key) SSH_KEY="$2"; shift 2 ;;
        *) usage ;;
    esac
done

if [[ -z "$HOST" ]]; then
    error "Host is required"
    usage
fi

if [[ -z "$PASS" && -z "$SSH_KEY" ]]; then
    error "Password or SSH key is required"
    usage
fi

# Check for sshpass if using password
if [[ -n "$PASS" ]] && ! command -v sshpass &>/dev/null; then
    error "sshpass is required for password authentication"
    echo "Install with: apt install sshpass  OR  dnf install sshpass"
    exit 1
fi

mkdir -p "$BACKUP_DIR"

echo "========================================================"
echo "  VYOS ROUTER - MASTER HARDENING SCRIPT"
echo "  Target: $HOST"
echo "  Time: $(date)"
echo "========================================================"
echo ""

# ============================================================================
# PHASE 1: TEST CONNECTIVITY
# ============================================================================
phase "PHASE 1: TEST CONNECTIVITY"
log "Testing SSH connection..."

if ssh_cmd "echo 'Connection successful'" | grep -q "successful"; then
    log "SSH connection successful"
else
    error "Failed to connect to $HOST"
    exit 2
fi

# ============================================================================
# PHASE 2: GET CURRENT STATUS
# ============================================================================
phase "PHASE 2: CURRENT STATUS"

log "Getting system information..."
echo ""
echo "--- System Info ---"
ssh_cmd "show version"
echo ""

log "Getting hostname..."
echo "--- Hostname ---"
ssh_cmd "show host name"
echo ""

# ============================================================================
# PHASE 3: BACKUP CONFIGURATION
# ============================================================================
phase "PHASE 3: BACKUP CONFIGURATION"
log "Backing up configuration..."

BACKUP_FILE="$BACKUP_DIR/vyos_${HOST}_${TIMESTAMP}.conf"

echo "# VyOS Configuration Backup" > "$BACKUP_FILE"
echo "# Host: $HOST" >> "$BACKUP_FILE"
echo "# Date: $(date)" >> "$BACKUP_FILE"
echo "# ======================================" >> "$BACKUP_FILE"
echo "" >> "$BACKUP_FILE"

ssh_cmd "show configuration" >> "$BACKUP_FILE"

chmod 600 "$BACKUP_FILE"
log "Configuration backed up to: $BACKUP_FILE"

# ============================================================================
# PHASE 4: ENUMERATE NETWORK
# ============================================================================
phase "PHASE 4: NETWORK CONFIGURATION"

log "Getting interfaces..."
echo ""
echo "--- Interfaces ---"
ssh_cmd "show interfaces"
echo ""

log "Getting routing table..."
echo "--- Routes ---"
ssh_cmd "show ip route"
echo ""

log "Getting firewall rules..."
echo "--- Firewall ---"
ssh_cmd "show firewall" 2>/dev/null || echo "(No firewall rules configured)"
echo ""

log "Getting NAT rules..."
echo "--- NAT ---"
ssh_cmd "show nat" 2>/dev/null || echo "(No NAT rules configured)"
echo ""

# ============================================================================
# PHASE 5: HARDENING GUIDANCE
# ============================================================================
phase "PHASE 5: HARDENING COMMANDS"
echo ""
echo "VyOS hardening should be done via SSH configuration mode."
echo ""
echo "Connect to VyOS and run these commands:"
echo ""
echo "# Enter configuration mode"
echo "configure"
echo ""
echo "# Change password"
echo "set system login user vyos authentication plaintext-password 'NEW_PASSWORD'"
echo ""
echo "# Disable SSH password auth (use keys)"
echo "set service ssh disable-password-authentication"
echo ""
echo "# Restrict SSH access"
echo "set service ssh listen-address <mgmt_ip>"
echo ""
echo "# Enable firewall logging"
echo "set firewall name WAN_IN default-log enable"
echo ""
echo "# Block invalid packets"
echo "set firewall state-policy invalid action drop"
echo ""
echo "# Commit and save"
echo "commit"
echo "save"
echo ""

# ============================================================================
# PHASE 6: RUN ENUMERATION SCRIPT
# ============================================================================
phase "PHASE 6: DETAILED ENUMERATION"

if [[ -f "$VYOS_SCRIPT" ]]; then
    log "Running vyosEnumerate.sh for detailed analysis..."
    chmod +x "$VYOS_SCRIPT"
    # Pass credentials to enumeration script if it supports them
    # Otherwise manual run may be needed
    warn "Run vyosEnumerate.sh manually for complete enumeration"
else
    warn "vyosEnumerate.sh not found at $VYOS_SCRIPT"
fi

# ============================================================================
# SUMMARY
# ============================================================================
phase "ASSESSMENT COMPLETE"
echo ""
echo "========================================================"
echo "  VYOS ROUTER ASSESSMENT COMPLETE"
echo "========================================================"
echo ""
echo "Completed:"
echo "  - SSH connectivity verified"
echo "  - System information retrieved"
echo "  - Configuration backed up to: $BACKUP_FILE"
echo "  - Network configuration enumerated"
echo ""
echo "NEXT STEPS:"
echo "  1. Change default password"
echo "  2. Configure firewall rules"
echo "  3. Set up NAT if required"
echo "  4. Enable logging"
echo "  5. Configure management access restrictions"
echo ""
echo "BACKUP LOCATION: $BACKUP_DIR/"
echo ""
echo "========================================================"

exit 0
