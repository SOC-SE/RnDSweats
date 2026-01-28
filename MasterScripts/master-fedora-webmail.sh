#!/bin/bash
# ==============================================================================
# Script Name: master-fedora-webmail.sh
# Description: Master hardening script for Fedora Webmail Server
#              Runs enumeration, hardening, backups, and post-hardening enum
# Target: Fedora 42 - Webmail Server (SMTP, POP3)
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Initial enumeration (masterEnum.sh)
#   2. General Linux hardening (generalLinuxHarden.sh)
#   3. Mail server hardening (mail_hardener.sh)
#   4. Firewall configuration (service-specific rules)
#   5. System backups (systemBackups.sh)
#   6. Post-hardening enumeration (masterEnum.sh)
#
# Services Protected: SMTP (25), POP3 (110), IMAP (143), Submission (587)
#
# Usage:
#   ./master-fedora-webmail.sh
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LINUXDEV="$REPO_DIR/LinuxDev"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/ccdc"
LOG_FILE="$LOG_DIR/master-fedora-webmail_$TIMESTAMP.log"

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
echo "  FEDORA WEBMAIL SERVER - MASTER HARDENING SCRIPT"
echo "  Target: Fedora 42 with Postfix/Dovecot (SMTP/POP3)"
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
# PHASE 3: MAIL SERVER HARDENING
# ============================================================================
phase "PHASE 3: MAIL SERVER HARDENING"

# Detect mail services
POSTFIX_ACTIVE=false
DOVECOT_ACTIVE=false

if systemctl is-active --quiet postfix 2>/dev/null; then
    log "Postfix detected and running"
    POSTFIX_ACTIVE=true
fi

if systemctl is-active --quiet dovecot 2>/dev/null; then
    log "Dovecot detected and running"
    DOVECOT_ACTIVE=true
fi

# Use Fedora-specific mail hardener if it exists, otherwise use general one
if [[ -f "$LINUXDEV/mail_hardener_fedora.sh" ]]; then
    run_script "$LINUXDEV/mail_hardener_fedora.sh" "Fedora Mail Hardening"
elif [[ -f "$LINUXDEV/mail_hardener.sh" ]]; then
    run_script "$LINUXDEV/mail_hardener.sh" "Mail Server Hardening"
else
    warn "No mail hardening script found"
fi

# ============================================================================
# PHASE 4: FIREWALL CONFIGURATION
# ============================================================================
phase "PHASE 4: FIREWALL CONFIGURATION"
log "Configuring firewall for mail services..."

# Use firewalld on Fedora
if command -v firewall-cmd &>/dev/null; then
    log "Using firewalld..."

    # Ensure firewalld is running
    systemctl enable --now firewalld

    # Get default zone
    ZONE=$(firewall-cmd --get-default-zone)

    # Remove unnecessary services
    firewall-cmd --permanent --zone="$ZONE" --remove-service=cockpit 2>/dev/null || true
    firewall-cmd --permanent --zone="$ZONE" --remove-service=dhcpv6-client 2>/dev/null || true

    # Add required services
    firewall-cmd --permanent --zone="$ZONE" --add-service=ssh
    firewall-cmd --permanent --zone="$ZONE" --add-service=smtp
    firewall-cmd --permanent --zone="$ZONE" --add-service=pop3
    firewall-cmd --permanent --zone="$ZONE" --add-service=imap
    firewall-cmd --permanent --zone="$ZONE" --add-port=587/tcp  # Submission

    # Reload
    firewall-cmd --reload

    log "Firewalld configured: SSH, SMTP(25), POP3(110), IMAP(143), Submission(587)"
else
    # Fallback to iptables
    log "Using iptables..."

    iptables -F INPUT 2>/dev/null || true
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Anti-reconnaissance
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -f -j DROP

    # ICMP
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

    # SSH
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min -j ACCEPT

    # Mail services (scored)
    iptables -A INPUT -p tcp --dport 25 -j ACCEPT   # SMTP
    iptables -A INPUT -p tcp --dport 110 -j ACCEPT  # POP3
    iptables -A INPUT -p tcp --dport 143 -j ACCEPT  # IMAP
    iptables -A INPUT -p tcp --dport 587 -j ACCEPT  # Submission

    # Secure versions (if needed)
    iptables -A INPUT -p tcp --dport 465 -j ACCEPT  # SMTPS
    iptables -A INPUT -p tcp --dport 993 -j ACCEPT  # IMAPS
    iptables -A INPUT -p tcp --dport 995 -j ACCEPT  # POP3S

    iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4

    iptables-save > /etc/sysconfig/iptables
    log "iptables configured for mail services"
fi

# ============================================================================
# PHASE 5: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 5: SYSTEM BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"

# Additional mail-specific backups
log "Backing up mail configuration..."
BACKUP_DIR="/root/mail_backup_$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

[[ -d /etc/postfix ]] && cp -a /etc/postfix "$BACKUP_DIR/"
[[ -d /etc/dovecot ]] && cp -a /etc/dovecot "$BACKUP_DIR/"
[[ -f /etc/aliases ]] && cp /etc/aliases "$BACKUP_DIR/"

log "Mail configs backed up to $BACKUP_DIR"

# ============================================================================
# PHASE 6: POST-HARDENING ENUMERATION
# ============================================================================
phase "PHASE 6: POST-HARDENING ENUMERATION"
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
echo "  FEDORA WEBMAIL SERVER HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "Logs saved to: $LOG_DIR/"
echo "Mail backup: $BACKUP_DIR"
echo ""
echo "NEXT STEPS:"
echo "  1. Run normalizeTools.sh to install additional tools"
echo "  2. Run persistenceHunter.sh and rootkitDetectionInstall.sh"
echo "  3. Install Salt minion and connect to SaltGUI"
echo "  4. Verify mail services are accessible"
echo ""
echo "SERVICE VERIFICATION:"
echo "  # Test SMTP"
echo "  nc -zv localhost 25"
echo "  # Test POP3"
echo "  nc -zv localhost 110"
echo "  # Check Postfix"
echo "  postfix status"
echo "  # Check Dovecot"
echo "  doveadm service status"
echo ""
echo "========================================================"

exit 0
