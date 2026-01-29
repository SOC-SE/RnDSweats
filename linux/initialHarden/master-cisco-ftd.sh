#!/bin/bash
# ==============================================================================
# Script Name: master-cisco-ftd.sh
# Description: Master script for Cisco FTD firewall initial hardening
#              Uses ciscoFtdManage.sh for SSH-based management
# Target: Cisco FTD 7.2.9
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Get current status
#   2. Backup configuration
#   3. Show interfaces and routes
#   4. Provide hardening guidance
#
# IMPORTANT: This script runs FROM your admin workstation, not ON the firewall
# NOTE: FTD has limited CLI capability - most config is via FMC
#
# Usage:
#   ./master-cisco-ftd.sh -H <ftd_ip> -u admin -p <password>
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
FTD_SCRIPT="$REPO_DIR/Tools/CiscoFTD/ciscoFtdManage.sh"
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
    echo "Usage: $0 -H <ftd_ip> -u <username> -p <password>"
    echo ""
    echo "Options:"
    echo "  -H, --host       FTD management IP (required)"
    echo "  -u, --user       SSH username (default: admin)"
    echo "  -p, --pass       SSH password (required)"
    echo "  -k, --key        SSH private key file (alternative to password)"
    echo "  --dry-run        Show what would be done"
    echo ""
    exit 1
}

# --- Parse Arguments ---
HOST=""
USER="admin"
PASS=""
SSH_KEY=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -H|--host) HOST="$2"; shift 2 ;;
        -u|--user) USER="$2"; shift 2 ;;
        -p|--pass) PASS="$2"; shift 2 ;;
        -k|--key) SSH_KEY="$2"; shift 2 ;;
        --dry-run) DRY_RUN="--dry-run"; shift ;;
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

# Check for management script
if [[ ! -f "$FTD_SCRIPT" ]]; then
    error "ciscoFtdManage.sh not found at $FTD_SCRIPT"
    exit 1
fi

chmod +x "$FTD_SCRIPT"

# Build auth args
AUTH_ARGS="-H $HOST -u $USER"
[[ -n "$PASS" ]] && AUTH_ARGS="$AUTH_ARGS -p $PASS"
[[ -n "$SSH_KEY" ]] && AUTH_ARGS="$AUTH_ARGS -k $SSH_KEY"

echo "========================================================"
echo "  CISCO FTD FIREWALL - MASTER HARDENING SCRIPT"
echo "  Target: $HOST"
echo "  Time: $(date)"
echo "========================================================"
echo ""
warn "NOTE: Cisco FTD has limited CLI configuration capability"
warn "Most configuration should be done via Firepower Management Center (FMC)"
echo ""

# ============================================================================
# PHASE 1: GET CURRENT STATUS
# ============================================================================
phase "PHASE 1: CURRENT STATUS"
log "Getting system status..."

# shellcheck disable=SC2086
"$FTD_SCRIPT" $AUTH_ARGS status $DRY_RUN

# ============================================================================
# PHASE 2: BACKUP CONFIGURATION
# ============================================================================
phase "PHASE 2: BACKUP CONFIGURATION"
log "Creating configuration backup..."

# shellcheck disable=SC2086
"$FTD_SCRIPT" $AUTH_ARGS -o "./ftd_backups" backup $DRY_RUN

if [[ $? -eq 0 ]]; then
    log "Backup completed successfully"
else
    warn "Backup may have issues - check output"
fi

# ============================================================================
# PHASE 3: SHOW NETWORK CONFIGURATION
# ============================================================================
phase "PHASE 3: NETWORK CONFIGURATION"

log "Getting interface configuration..."
# shellcheck disable=SC2086
"$FTD_SCRIPT" $AUTH_ARGS interfaces $DRY_RUN

log "Getting routing table..."
# shellcheck disable=SC2086
"$FTD_SCRIPT" $AUTH_ARGS routes $DRY_RUN

# ============================================================================
# PHASE 4: SHOW ACTIVE SESSIONS
# ============================================================================
phase "PHASE 4: ACTIVE SESSIONS"
log "Getting active connections..."

# shellcheck disable=SC2086
"$FTD_SCRIPT" $AUTH_ARGS sessions $DRY_RUN

# ============================================================================
# PHASE 5: HARDENING GUIDANCE
# ============================================================================
phase "PHASE 5: HARDENING GUIDANCE"
echo ""
echo "Cisco FTD hardening should be performed via FMC or CLI:"
echo ""
echo "CLI Hardening (via SSH):"
echo "  1. Change admin password:"
echo "     configure user admin password"
echo ""
echo "  2. Check management access:"
echo "     show managers"
echo ""
echo "  3. Check access policies:"
echo "     show access-list"
echo ""
echo "FMC Hardening (recommended):"
echo "  1. Review and tighten Access Control Policies"
echo "  2. Enable Intrusion Prevention (IPS)"
echo "  3. Configure Security Intelligence feeds"
echo "  4. Enable malware detection"
echo "  5. Configure logging to Splunk/SIEM"
echo "  6. Review NAT rules"
echo ""
echo "To change password interactively:"
echo "  $FTD_SCRIPT $AUTH_ARGS passwd"
echo ""

# ============================================================================
# SUMMARY
# ============================================================================
phase "ASSESSMENT COMPLETE"
echo ""
echo "========================================================"
echo "  CISCO FTD FIREWALL ASSESSMENT COMPLETE"
echo "========================================================"
echo ""
echo "Completed:"
echo "  - System status retrieved"
echo "  - Configuration backed up"
echo "  - Interface and routing info captured"
echo "  - Active sessions reviewed"
echo ""
echo "NEXT STEPS:"
echo "  1. Change admin password"
echo "  2. Review access policies in FMC"
echo "  3. Enable threat prevention features"
echo "  4. Configure logging to SIEM"
echo ""
echo "BACKUP LOCATION: ./ftd_backups/"
echo ""
echo "========================================================"

exit 0
