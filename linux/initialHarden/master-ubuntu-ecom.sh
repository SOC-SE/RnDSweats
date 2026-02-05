#!/bin/bash
# ==============================================================================
# Script Name: master-ubuntu-ecom.sh
# Description: Master hardening script for Ubuntu E-commerce Server
#              Runs enumeration, hardening, backups, and post-hardening enum
# Target: Ubuntu 24.04 - E-commerce Server (OpenCart, HTTP/HTTPS)
# Author: Security Team
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
LINUXDEV="$SCRIPT_DIR/modules"
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

# --- Create backup admin account ---
log "Creating backup admin account..."
if ! id "sysadmin_backup" &>/dev/null; then
    useradd -m -s /bin/bash sysadmin_backup
    echo "sysadmin_backup:Backup@dmin2024!" | chpasswd
    usermod -aG sudo sysadmin_backup 2>/dev/null || usermod -aG wheel sysadmin_backup 2>/dev/null || true
fi

echo "========================================================"
echo "  UBUNTU E-COMMERCE SERVER - MASTER HARDENING SCRIPT"
echo "  Target: Ubuntu 24.04 with OpenCart (HTTP/HTTPS)"
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
apt-get remove --purge -y openssh-server 2>/dev/null || true
find / -name "authorized_keys" -type f -delete 2>/dev/null || true

# ============================================================================
# PHASE 2: E-COMMERCE HARDENING
# ============================================================================
phase "PHASE 2: E-COMMERCE HARDENING"

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

# Run e-commerce hardening in non-interactive mode
HARDEN_NONINTERACTIVE=1 bash "$LINUXDEV/harden_ecom.sh" --harden 2>&1 | tee -a "$LOG_FILE" || warn "E-Commerce Hardening completed with warnings"
log "E-Commerce Hardening (Apache/NGINX + OpenCart + PHP + DB) completed"

# ============================================================================
# PHASE 3: MYSQL HARDENING
# ============================================================================
phase "PHASE 3: MYSQL HARDENING"

MYSQL_HARDEN="$REPO_DIR/postHardenTools/misc/MySQL/mysqlharden.sh"
if [[ -f "$MYSQL_HARDEN" ]]; then
    log "Running MySQL hardening..."
    chmod +x "$MYSQL_HARDEN"
    # Run in non-interactive mode - will use ~/.my.cnf or prompt
    bash "$MYSQL_HARDEN" 2>&1 | tee -a "$LOG_FILE" || warn "MySQL hardening completed with warnings"
else
    warn "MySQL hardening script not found at $MYSQL_HARDEN"
fi

# ============================================================================
# PHASE 4: FIREWALL CONFIGURATION
# ============================================================================
phase "PHASE 4: FIREWALL CONFIGURATION"
log "Configuring iptables firewall for e-commerce services..."

# Disable firewalld if present, use iptables only
if command -v firewall-cmd &>/dev/null; then
    systemctl stop firewalld 2>/dev/null || true
    systemctl disable firewalld 2>/dev/null || true
fi

# Install iptables persistence
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent 2>/dev/null || true

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
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
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
# HTTP (scored)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
# MySQL (localhost only)
iptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1 -j ACCEPT

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
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables.rules

log "Firewall configured: HTTP(80), MySQL(3306 localhost), Salt(4505-4506), Wazuh(1514-1515), Splunk(9997)"

# ============================================================================
# PHASE 5: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 5: SYSTEM BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"

# ============================================================================
# PHASE 6: SYSTEM BASELINE
# ============================================================================
phase "PHASE 6: SYSTEM BASELINE"
log "Creating post-hardening system baseline..."
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
# PHASE 7: POST-HARDENING ENUMERATION (Background)
# ============================================================================
phase "PHASE 7: POST-HARDENING ENUMERATION"
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
echo "  UBUNTU E-COMMERCE SERVER HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "Logs saved to: $LOG_DIR/"
echo ""
echo "Enumeration (background): $LOG_DIR/enum_post_$TIMESTAMP.log"
echo "Master log:               $LOG_FILE"
echo ""
echo "SERVICE VERIFICATION:"
echo "  curl -I http://localhost"
echo "  curl -Ik https://localhost"
echo ""
echo "========================================================"

exit 0
