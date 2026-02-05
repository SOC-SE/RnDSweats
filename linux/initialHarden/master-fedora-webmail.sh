#!/bin/bash
# ==============================================================================
# Script Name: master-fedora-webmail.sh
# Description: Master hardening script for Fedora Webmail Server
#              Runs enumeration, hardening, backups, and post-hardening enum
# Target: Fedora 42 - Webmail Server (SMTP, POP3)
# Author: Security Team
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
LINUXDEV="$SCRIPT_DIR/modules"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
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

# --- Create backup admin account ---
log "Creating backup admin account..."
if ! id "sysadmin_backup" &>/dev/null; then
    useradd -m -s /bin/bash sysadmin_backup
    echo "sysadmin_backup:Backup@dmin2024!" | chpasswd
    usermod -aG wheel sysadmin_backup 2>/dev/null || usermod -aG sudo sysadmin_backup 2>/dev/null || true
fi

echo "========================================================"
echo "  FEDORA WEBMAIL SERVER - MASTER HARDENING SCRIPT"
echo "  Target: Fedora 42 with Postfix/Dovecot (SMTP/POP3)"
echo "  Time: $(date)"
echo "========================================================"
echo ""

# ============================================================================
# PHASE 1: GENERAL LINUX HARDENING
# ============================================================================
phase "PHASE 1: GENERAL LINUX HARDENING"
run_script "$LINUXDEV/generalLinuxHarden.sh" "General Linux Hardening"

# SSH removal
log "Removing SSH server..."
dnf remove -y openssh-server 2>/dev/null || yum remove -y openssh-server 2>/dev/null || true
find / -name "authorized_keys" -type f -delete 2>/dev/null || true

# ============================================================================
# PHASE 2: MAIL SERVER HARDENING
# ============================================================================
phase "PHASE 2: MAIL SERVER HARDENING"

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

run_script "$LINUXDEV/mail_hardener.sh" "Mail Server Hardening"

# ============================================================================
# PHASE 2b: MARIADB HARDENING
# ============================================================================
phase "PHASE 2b: MARIADB HARDENING"

if systemctl is-active --quiet mariadb 2>/dev/null; then
    log "MariaDB detected, running database hardening..."
    MYSQL_HARDEN="$REPO_DIR/postHardenTools/misc/MySQL/mysqlharden.sh"
    if [[ -f "$MYSQL_HARDEN" ]]; then
        chmod +x "$MYSQL_HARDEN"
        bash "$MYSQL_HARDEN" 2>&1 | tee -a "$LOG_FILE" || warn "MariaDB hardening completed with warnings"
    else
        warn "MySQL hardening script not found at $MYSQL_HARDEN"
        # Fallback: at minimum bind to localhost
        log "Applying minimal MariaDB hardening (bind to localhost)..."
        mariadb_conf=""
        if [[ -f /etc/my.cnf.d/mariadb-server.cnf ]]; then
            mariadb_conf="/etc/my.cnf.d/mariadb-server.cnf"
        elif [[ -f /etc/my.cnf ]]; then
            mariadb_conf="/etc/my.cnf"
        fi
        if [[ -n "$mariadb_conf" ]]; then
            if grep -q '^\[mysqld\]' "$mariadb_conf"; then
                if grep -q '^bind-address' "$mariadb_conf"; then
                    sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$mariadb_conf"
                else
                    sed -i '/^\[mysqld\]/a bind-address = 127.0.0.1' "$mariadb_conf"
                fi
            fi
            systemctl restart mariadb 2>/dev/null || true
            log "MariaDB bound to localhost"
        fi
    fi
else
    log "MariaDB not detected, skipping database hardening"
fi

# ============================================================================
# PHASE 3: FIREWALL CONFIGURATION
# ============================================================================
phase "PHASE 3: FIREWALL CONFIGURATION"
log "Configuring iptables firewall for mail services..."

# Disable and remove cockpit
log "Disabling and removing cockpit..."
systemctl stop cockpit.socket cockpit.service 2>/dev/null || true
systemctl disable cockpit.socket cockpit.service 2>/dev/null || true
dnf remove -y cockpit cockpit-ws cockpit-bridge cockpit-system 2>/dev/null || true

# Disable and remove firewalld (iptables only)
log "Disabling and removing firewalld..."
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true
dnf remove -y firewalld 2>/dev/null || true

# Install iptables persistence
dnf install -y iptables-services 2>/dev/null || true

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Default policies (safety net behind explicit REJECT rules)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP (all - required by competition rules)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Anti-reconnaissance: Bad TCP flags
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -f -j DROP

# Drop invalid state packets (malformed/scan artifacts)
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# SYN rate limiting (slow down port scans - 25 new connections/sec per source IP)
iptables -A INPUT -p tcp --syn -m hashlimit \
    --hashlimit-above 25/sec --hashlimit-burst 50 \
    --hashlimit-mode srcip --hashlimit-name syn_scan \
    --hashlimit-htable-expire 30000 -j DROP

# --- Outbound: DNS, HTTP, HTTPS (for updates/tooling) ---
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# --- Inbound: Scored services ---
# SMTP (scored)
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
# POP3 (scored)
iptables -A INPUT -p tcp --dport 110 -j ACCEPT
# Submission (authenticated mail sending)
iptables -A INPUT -p tcp --dport 587 -j ACCEPT

# IMAP (uncomment if needed)
#iptables -A INPUT -p tcp --dport 143 -j ACCEPT

# Secure mail ports (uncomment if TLS required)
#iptables -A INPUT -p tcp --dport 993 -j ACCEPT   # IMAPS
#iptables -A INPUT -p tcp --dport 995 -j ACCEPT   # POP3S
#iptables -A INPUT -p tcp --dport 465 -j ACCEPT   # SMTPS

#Test - Daut - WindowsAD Fix
#iptables -A INPUT -p tcp --dport 464 -j ACCEPT
#iptables -A INPUT -p udp --dport 464 -j ACCEPT
#iptables -A INPUT -p tcp --dport 88 -j ACCEPT
#iptables -A INPUT -p udp --dport 88 -j ACCEPT
#iptables -A INPUT -p tcp --dport 389 -j ACCEPT
#iptables -A INPUT -p udp --dport 389 -j ACCEPT
#iptables -A INPUT -p tcp --dport 636 -j ACCEPT
#iptables -A INPUT -p udp --dport 636 -j ACCEPT
#iptables -A OUTPUT -p tcp --dport 464 -j ACCEPT
#iptables -A OUTPUT -p udp --dport 464 -j ACCEPT
#iptables -A OUTPUT -p tcp --dport 88 -j ACCEPT
#iptables -A OUTPUT -p udp --dport 88 -j ACCEPT
#iptables -A OUTPUT -p tcp --dport 389 -j ACCEPT
#iptables -A OUTPUT -p udp --dport 389 -j ACCEPT
#iptables -A OUTPUT -p tcp --dport 636 -j ACCEPT
#iptables -A OUTPUT -p udp --dport 636 -j ACCEPT

# --- Outbound: Salt Minion (connects to Salt Master) ---
iptables -A OUTPUT -p tcp --dport 4505 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 4506 -j ACCEPT

# --- Outbound: Wazuh Agent (connects to Wazuh Manager) ---
iptables -A OUTPUT -p tcp --dport 1514 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1515 -j ACCEPT

# --- Outbound: Splunk Universal Forwarder (sends logs to indexer) ---
iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# --- Logging for all dropped/rejected packets ---
iptables -A INPUT -j LOG --log-prefix "IPT-INPUT-REJECT: " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "IPT-OUTPUT-REJECT: " --log-level 4
iptables -A FORWARD -j LOG --log-prefix "IPT-FORWARD-REJECT: " --log-level 4

# --- Default REJECT ---
iptables -A INPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable

# Save rules
iptables-save > /etc/sysconfig/iptables
systemctl enable iptables 2>/dev/null || true
systemctl start iptables 2>/dev/null || true

log "Firewall configured: SMTP(25), POP3(110), Submission(587), Salt(4505-4506), Wazuh(1514-1515), Splunk(9997)"

# ============================================================================
# PHASE 4: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 4: SYSTEM BACKUPS"
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
# PHASE 5: SYSTEM BASELINE
# ============================================================================
phase "PHASE 5: SYSTEM BASELINE"
log "Creating post-hardening system baseline..."
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
# PHASE 6: POST-HARDENING ENUMERATION (Background)
# ============================================================================
phase "PHASE 6: POST-HARDENING ENUMERATION"
if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    log "Starting enumeration in background..."
    nohup bash "$LINUXDEV/masterEnum.sh" > "$LOG_DIR/enum_post_$TIMESTAMP.log" 2>&1 &
    log "Enumeration running in background (PID: $!) - output: $LOG_DIR/enum_post_$TIMESTAMP.log"
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
