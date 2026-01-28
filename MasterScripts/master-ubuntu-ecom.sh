#!/bin/bash
# ==============================================================================
# Script Name: master-ubuntu-ecom.sh
# Description: Master hardening script for Ubuntu E-commerce Server
#              Runs enumeration, hardening, backups, and post-hardening enum
# Target: Ubuntu 24.04 - E-commerce Server (OpenCart, HTTP/HTTPS)
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Initial enumeration (masterEnum.sh)
#   2. General Linux hardening (generalLinuxHarden.sh)
#   3. Web server hardening (harden_ecom.sh)
#   4. OpenCart hardening (harden_ecom.sh)
#   5. Firewall configuration (service-specific rules)
#   6. System backups (systemBackups.sh)
#   7. Post-hardening enumeration (masterEnum.sh)
#
# Services Protected: HTTP (80), HTTPS (443)
#
# Usage:
#   ./master-ubuntu-ecom.sh
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LINUXDEV="$REPO_DIR/LinuxDev"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/master-ubuntu-ecom_$TIMESTAMP.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
echo "  UBUNTU E-COMMERCE SERVER - MASTER HARDENING SCRIPT"
echo "  Target: Ubuntu 24.04 with OpenCart (HTTP/HTTPS)"
echo "  Time: $(date)"
echo "========================================================"
echo ""

# ============================================================================
# PHASE 1: INITIAL ENUMERATION
# ============================================================================
phase "PHASE 1: INITIAL ENUMERATION"
log "Capturing pre-hardening system state..."

if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    chmod +x "$LINUXDEV/masterEnum.sh"
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_pre_$TIMESTAMP.log"
    log "Pre-hardening enumeration saved to $LOG_DIR/enum_pre_$TIMESTAMP.log"
else
    warn "masterEnum.sh not found, skipping initial enumeration"
fi

# ============================================================================
# PHASE 2: GENERAL LINUX HARDENING
# ============================================================================
phase "PHASE 2: GENERAL LINUX HARDENING"
run_script "$LINUXDEV/generalLinuxHarden.sh" "General Linux Hardening"

# ============================================================================
# PHASE 3: WEB SERVER HARDENING
# ============================================================================
phase "PHASE 3: E-COMMERCE HARDENING"

# Determine web server type
if systemctl is-active --quiet apache2 2>/dev/null; then
    log "Apache detected"
    WEB_SERVER="apache"
elif systemctl is-active --quiet nginx 2>/dev/null; then
    log "NGINX detected"
    WEB_SERVER="nginx"
else
    warn "No web server detected, applying general web hardening"
    WEB_SERVER="unknown"
fi

run_script "$LINUXDEV/harden_ecom.sh" "E-Commerce Hardening (Apache/NGINX + OpenCart + PHP + DB)"

# ============================================================================
# PHASE 4: FIREWALL CONFIGURATION
# ============================================================================
phase "PHASE 5: FIREWALL CONFIGURATION"
log "Configuring firewall for e-commerce services..."

# Flush existing rules (careful!)
iptables -F INPUT 2>/dev/null || true

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Anti-reconnaissance: Bad TCP flags
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -f -j DROP

# ICMP (limited)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT

# SSH (restrict as needed)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT

# HTTP/HTTPS (scored services)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# MySQL (localhost only, if running)
iptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4 --log-ip-options

# Save rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables.rules
    log "iptables rules saved to /etc/iptables.rules"
fi

log "Firewall configured: SSH(22), HTTP(80), HTTPS(443)"

# ============================================================================
# PHASE 6: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 6: SYSTEM BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"

# ============================================================================
# PHASE 7: SYSTEM BASELINE
# ============================================================================
phase "PHASE 7: SYSTEM BASELINE"
log "Creating post-hardening system baseline..."
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
# PHASE 8: POST-HARDENING ENUMERATION
# ============================================================================
phase "PHASE 8: POST-HARDENING ENUMERATION"
log "Capturing post-hardening system state..."

if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_post_$TIMESTAMP.log"
    log "Post-hardening enumeration saved to $LOG_DIR/enum_post_$TIMESTAMP.log"
fi

# ============================================================================
# SUMMARY
# ============================================================================
phase "HARDENING COMPLETE"
echo ""
echo "========================================================"
echo "  UBUNTU E-COMMERCE SERVER HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "Logs saved to: $LOG_DIR/"
echo ""
echo "Pre-hardening enum:  $LOG_DIR/enum_pre_$TIMESTAMP.log"
echo "Post-hardening enum: $LOG_DIR/enum_post_$TIMESTAMP.log"
echo "Master log:          $LOG_FILE"
echo ""
echo "NEXT STEPS:"
echo "  1. Run normalizeTools.sh to install additional tools"
echo "  2. Run persistenceHunter.sh and rootkitDetectionInstall.sh"
echo "  3. Install Salt minion and connect to SaltGUI"
echo "  4. Verify HTTP/HTTPS services are accessible"
echo ""
echo "SERVICE VERIFICATION:"
echo "  curl -I http://localhost"
echo "  curl -Ik https://localhost"
echo ""
echo "========================================================"

exit 0
