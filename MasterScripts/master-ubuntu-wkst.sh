#!/bin/bash
# ==============================================================================
# Script Name: master-ubuntu-wkst.sh
# Description: Master hardening script for Ubuntu Workstation
#              Minimal services, focus on endpoint security
# Target: Ubuntu 24.04 - Workstation
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Initial enumeration (masterEnum.sh)
#   2. General Linux hardening (generalLinuxHarden.sh)
#   3. Firewall configuration (minimal services)
#   4. System backups (systemBackups.sh)
#   5. Post-hardening enumeration (masterEnum.sh)
#
# Services Protected: SSH (22) only - workstation has minimal exposure
#
# Usage:
#   ./master-ubuntu-wkst.sh
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LINUXDEV="$REPO_DIR/LinuxDev"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/master-ubuntu-wkst_$TIMESTAMP.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helper Functions ---
log() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
phase() { echo -e "\n${CYAN}========== $1 ==========${NC}" | tee -a "$LOG_FILE"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

run_script() {
    local script="$1"
    local name="$2"

    if [[ -f "$script" ]]; then
        log "Running $name..."
        chmod +x "$script"
        bash "$script" 2>&1 | tee -a "$LOG_FILE"
        log "$name completed"
    else
        warn "Script not found: $script"
    fi
}

# --- Main ---
check_root
mkdir -p "$LOG_DIR"

echo "========================================================"
echo "  UBUNTU WORKSTATION - MASTER HARDENING SCRIPT"
echo "  Target: Ubuntu 24.04 Workstation"
echo "  Time: $(date)"
echo "========================================================"
echo ""

# ============================================================================
# PHASE 1: INITIAL ENUMERATION
# ============================================================================
phase "PHASE 1: INITIAL ENUMERATION"
if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    chmod +x "$LINUXDEV/masterEnum.sh"
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_pre_$TIMESTAMP.log"
fi

# ============================================================================
# PHASE 2: GENERAL LINUX HARDENING
# ============================================================================
phase "PHASE 2: GENERAL LINUX HARDENING"
run_script "$LINUXDEV/generalLinuxHarden.sh" "General Linux Hardening"

# ============================================================================
# PHASE 3: FIREWALL CONFIGURATION
# ============================================================================
phase "PHASE 3: FIREWALL CONFIGURATION"
log "Configuring restrictive firewall for workstation..."

# Very restrictive - workstation doesn't need to accept connections
iptables -F INPUT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Anti-recon
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -f -j DROP

# ICMP (limited)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# SSH only (for admin access)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min -j ACCEPT

# Log drops
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
else
    iptables-save > /etc/iptables.rules
fi

log "Firewall configured: SSH(22) only"

# ============================================================================
# PHASE 4: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 4: SYSTEM BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"

# ============================================================================
# PHASE 5: SYSTEM BASELINE
# ============================================================================
phase "PHASE 5: SYSTEM BASELINE"
log "Creating post-hardening system baseline..."
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
# PHASE 6: POST-HARDENING ENUMERATION
# ============================================================================
phase "PHASE 6: POST-HARDENING ENUMERATION"
if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_post_$TIMESTAMP.log"
fi

# ============================================================================
# SUMMARY
# ============================================================================
phase "HARDENING COMPLETE"
echo ""
echo "========================================================"
echo "  UBUNTU WORKSTATION HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "This is a LOW PRIORITY box (workstation, not scored)"
echo ""
echo "NEXT STEPS:"
echo "  1. Run normalizeTools.sh"
echo "  2. Run persistenceHunter.sh"
echo "  3. Install Salt minion"
echo ""
echo "========================================================"

exit 0
