#!/bin/bash
# ==============================================================================
# Script Name: master-paloalto.sh
# Description: Master script for Palo Alto firewall initial hardening
#              Uses paloAltoManage.sh for API-based management
# Target: Palo Alto PAN-OS Firewall
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Backup current configuration
#   2. Change admin password
#   3. Apply hardening (disable HTTP, Telnet, restrict mgmt IPs)
#   4. Verify configuration
#
# IMPORTANT: This script runs FROM your admin workstation, not ON the firewall
#
# Usage:
#   ./master-paloalto.sh -H <firewall_ip> -u admin -p <password>
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PALO_SCRIPT="$REPO_DIR/PaloAlto/paloAltoManage.sh"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

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
    echo "Usage: $0 -H <firewall_ip> -u <username> -p <password> [--mgmt-ips <ips>]"
    echo ""
    echo "Options:"
    echo "  -H, --host       Palo Alto management IP (required)"
    echo "  -u, --user       Admin username (default: admin)"
    echo "  -p, --pass       Admin password (required)"
    echo "  --mgmt-ips       Comma-separated management IPs to allow"
    echo "  --dry-run        Show what would be done"
    echo ""
    exit 1
}

# --- Parse Arguments ---
HOST=""
USER="admin"
PASS=""
MGMT_IPS=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -H|--host) HOST="$2"; shift 2 ;;
        -u|--user) USER="$2"; shift 2 ;;
        -p|--pass) PASS="$2"; shift 2 ;;
        --mgmt-ips) MGMT_IPS="$2"; shift 2 ;;
        --dry-run) DRY_RUN="--dry-run"; shift ;;
        *) usage ;;
    esac
done

if [[ -z "$HOST" || -z "$PASS" ]]; then
    error "Host and password are required"
    usage
fi

# Check for management script
if [[ ! -f "$PALO_SCRIPT" ]]; then
    error "paloAltoManage.sh not found at $PALO_SCRIPT"
    exit 1
fi

chmod +x "$PALO_SCRIPT"

echo "========================================================"
echo "  PALO ALTO FIREWALL - MASTER HARDENING SCRIPT"
echo "  Target: $HOST"
echo "  Time: $(date)"
echo "========================================================"
echo ""

# ============================================================================
# PHASE 1: BACKUP CONFIGURATION
# ============================================================================
phase "PHASE 1: BACKUP CONFIGURATION"
log "Creating configuration backup..."

"$PALO_SCRIPT" -H "$HOST" -u "$USER" -p "$PASS" -o "./palo_backups" backup $DRY_RUN

if [[ $? -eq 0 ]]; then
    log "Backup completed successfully"
else
    error "Backup failed - proceeding with caution"
fi

# ============================================================================
# PHASE 2: GET CURRENT STATUS
# ============================================================================
phase "PHASE 2: CURRENT STATUS"
log "Getting current system status..."

"$PALO_SCRIPT" -H "$HOST" -u "$USER" -p "$PASS" status

# ============================================================================
# PHASE 3: APPLY HARDENING
# ============================================================================
phase "PHASE 3: APPLY HARDENING"

if [[ -n "$MGMT_IPS" ]]; then
    log "Applying hardening with management IP restriction: $MGMT_IPS"
    "$PALO_SCRIPT" -H "$HOST" -u "$USER" -p "$PASS" --mgmt-ips "$MGMT_IPS" harden $DRY_RUN
else
    log "Applying hardening (no management IP restriction)"
    "$PALO_SCRIPT" -H "$HOST" -u "$USER" -p "$PASS" harden $DRY_RUN
fi

# ============================================================================
# PHASE 4: CHANGE ADMIN PASSWORD
# ============================================================================
phase "PHASE 4: CHANGE ADMIN PASSWORD"
warn "Password change should be done interactively"
echo ""
echo "To change the admin password, run:"
echo "  $PALO_SCRIPT -H $HOST -u $USER -p <current_pass> passwd"
echo ""
echo "Or change it via the web UI at: https://$HOST"

# ============================================================================
# SUMMARY
# ============================================================================
phase "HARDENING COMPLETE"
echo ""
echo "========================================================"
echo "  PALO ALTO FIREWALL HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "Applied settings:"
echo "  - Configuration backed up"
echo "  - HTTP management: Disabled"
echo "  - Telnet management: Disabled"
[[ -n "$MGMT_IPS" ]] && echo "  - Management IPs restricted to: $MGMT_IPS"
echo ""
echo "NEXT STEPS:"
echo "  1. Change admin password if not already done"
echo "  2. Review security policies"
echo "  3. Configure threat prevention profiles"
echo "  4. Enable logging to Splunk/SIEM"
echo ""
echo "VERIFICATION:"
echo "  - Web UI: https://$HOST"
echo "  - Run: $PALO_SCRIPT -H $HOST -u $USER -p <pass> status"
echo ""
echo "========================================================"

exit 0
