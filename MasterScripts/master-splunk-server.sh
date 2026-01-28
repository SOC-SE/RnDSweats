#!/bin/bash
# ==============================================================================
# Script Name: master-splunk-server.sh
# Description: Master hardening script for Splunk/SIEM Server
#              This is the CRITICAL infrastructure box - handles with care
# Target: Oracle Linux 9.2 - Splunk Server (also hosts SaltGUI, Wazuh, DNS)
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Workflow:
#   1. Initial enumeration (masterEnum.sh)
#   2. Splunk-specific hardening (masterHardenSplunk.sh)
#   3. Minimal general hardening (avoid breaking Splunk)
#   4. Firewall configuration (service-specific rules)
#   5. System backups (systemBackups.sh)
#   6. Post-hardening enumeration (masterEnum.sh)
#
# Services Protected: Splunk (8000, 8089, 9997), SSH (22)
# Future Services: SaltGUI, Wazuh Server, DNS
#
# WARNING: This is a critical infrastructure box. Be careful with hardening!
#
# Usage:
#   ./master-splunk-server.sh
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LINUXDEV="$REPO_DIR/LinuxDev"
TOOLS="$REPO_DIR/Tools"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/master-splunk-server_$TIMESTAMP.log"

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
echo "  SPLUNK/SIEM SERVER - MASTER HARDENING SCRIPT"
echo "  Target: Oracle Linux 9.2 with Splunk"
echo "  Time: $(date)"
echo "  WARNING: Critical infrastructure - proceed carefully!"
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
fi

# ============================================================================
# PHASE 2: SPLUNK-SPECIFIC HARDENING
# ============================================================================
phase "PHASE 2: SPLUNK-SPECIFIC HARDENING"

# Check if Splunk is running
if pgrep -f splunkd &>/dev/null; then
    log "Splunk daemon detected"
else
    warn "Splunk not detected - may need to start it first"
fi

# Run Splunk hardening script
if [[ -f "$TOOLS/Splunk/masterHardenSplunk.sh" ]]; then
    run_script "$TOOLS/Splunk/masterHardenSplunk.sh" "Splunk Hardening"
else
    warn "masterHardenSplunk.sh not found"
    log "Applying manual Splunk hardening..."

    # Basic Splunk hardening if script not found
    SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"

    if [[ -d "$SPLUNK_HOME" ]]; then
        # Secure file permissions
        chmod 700 "$SPLUNK_HOME/etc"
        chmod 600 "$SPLUNK_HOME/etc/passwd" 2>/dev/null || true

        log "Basic Splunk permissions secured"
    fi
fi

# ============================================================================
# PHASE 3: MINIMAL GENERAL HARDENING
# ============================================================================
phase "PHASE 3: MINIMAL GENERAL HARDENING (Splunk-Safe)"
log "Applying minimal hardening to avoid breaking Splunk..."

# Kernel hardening via sysctl (safe for Splunk)
log "Applying kernel sysctl hardening..."
SYSCTL_HARDEN="/etc/sysctl.d/99-ccdc-hardening.conf"
[[ -f "$SYSCTL_HARDEN" ]] && cp "$SYSCTL_HARDEN" "${SYSCTL_HARDEN}.backup"
cat > "$SYSCTL_HARDEN" << 'SYSCTL_EOF'
# CCDC Kernel Hardening
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
# IPv6 - DISABLE (competition is IPv4-only)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
vm.mmap_min_addr = 65536
SYSCTL_EOF
sysctl -p "$SYSCTL_HARDEN" >/dev/null 2>&1 || true
log "Kernel hardening applied"

# SSH hardening (always safe)
if [[ -f "$LINUXDEV/ssh_harden.sh" ]]; then
    run_script "$LINUXDEV/ssh_harden.sh" "SSH Hardening"
fi

# PAM audit (non-destructive)
if [[ -f "$LINUXDEV/pamManager.sh" ]]; then
    log "Running PAM audit (read-only)..."
    bash "$LINUXDEV/pamManager.sh" audit -q 2>&1 | tee -a "$LOG_FILE" || true
fi

# NOTE: We skip generalLinuxHarden.sh as it may be too aggressive for Splunk

# ============================================================================
# PHASE 4: FIREWALL CONFIGURATION
# ============================================================================
phase "PHASE 4: FIREWALL CONFIGURATION"
log "Configuring firewall for Splunk and infrastructure services..."

# Use firewalld on Oracle Linux
if command -v firewall-cmd &>/dev/null; then
    systemctl enable --now firewalld

    ZONE=$(firewall-cmd --get-default-zone)

    # Splunk ports
    firewall-cmd --permanent --zone="$ZONE" --add-port=8000/tcp  # Splunk Web
    firewall-cmd --permanent --zone="$ZONE" --add-port=8089/tcp  # Splunk Management
    firewall-cmd --permanent --zone="$ZONE" --add-port=9997/tcp  # Splunk Forwarder receiving
    firewall-cmd --permanent --zone="$ZONE" --add-port=8088/tcp  # HTTP Event Collector

    # SSH
    firewall-cmd --permanent --zone="$ZONE" --add-service=ssh

    # Future services (SaltGUI, Wazuh, DNS)
    firewall-cmd --permanent --zone="$ZONE" --add-port=4505/tcp  # Salt publish
    firewall-cmd --permanent --zone="$ZONE" --add-port=4506/tcp  # Salt return
    firewall-cmd --permanent --zone="$ZONE" --add-port=1514/tcp  # Wazuh agent
    firewall-cmd --permanent --zone="$ZONE" --add-port=1515/tcp  # Wazuh registration
    firewall-cmd --permanent --zone="$ZONE" --add-port=55000/tcp # Wazuh API
    firewall-cmd --permanent --zone="$ZONE" --add-service=dns    # DNS

    # Remove unnecessary
    firewall-cmd --permanent --zone="$ZONE" --remove-service=cockpit 2>/dev/null || true

    firewall-cmd --reload
    log "Firewalld configured for Splunk and infrastructure services"
else
    # Fallback to iptables
    iptables -F INPUT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Anti-recon
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -f -j DROP

    # SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # Splunk
    iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8089 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8088 -j ACCEPT

    # Salt
    iptables -A INPUT -p tcp --dport 4505 -j ACCEPT
    iptables -A INPUT -p tcp --dport 4506 -j ACCEPT

    # Wazuh
    iptables -A INPUT -p tcp --dport 1514 -j ACCEPT
    iptables -A INPUT -p tcp --dport 1515 -j ACCEPT
    iptables -A INPUT -p tcp --dport 55000 -j ACCEPT

    # DNS
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j ACCEPT

    iptables-save > /etc/sysconfig/iptables
    log "iptables configured"
fi

# ============================================================================
# PHASE 5: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 5: SYSTEM BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"

# Splunk-specific backup
log "Backing up Splunk configuration..."
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
BACKUP_DIR="/root/splunk_backup_$TIMESTAMP"

if [[ -d "$SPLUNK_HOME" ]]; then
    mkdir -p "$BACKUP_DIR"
    cp -a "$SPLUNK_HOME/etc" "$BACKUP_DIR/"
    log "Splunk config backed up to $BACKUP_DIR"
fi

# ============================================================================
# PHASE 6: SYSTEM BASELINE
# ============================================================================
phase "PHASE 6: SYSTEM BASELINE"
log "Creating post-hardening system baseline..."
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
# PHASE 7: POST-HARDENING ENUMERATION
# ============================================================================
phase "PHASE 7: POST-HARDENING ENUMERATION"

if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_post_$TIMESTAMP.log"
fi

# ============================================================================
# SUMMARY
# ============================================================================
phase "HARDENING COMPLETE"
echo ""
echo "========================================================"
echo "  SPLUNK/SIEM SERVER HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "Logs: $LOG_DIR/"
echo "Splunk backup: $BACKUP_DIR"
echo ""
echo "CRITICAL: This box will host:"
echo "  - Splunk (scored service)"
echo "  - SaltGUI (management)"
echo "  - Wazuh Server (SIEM)"
echo "  - DNS Server"
echo ""
echo "NEXT STEPS:"
echo "  1. Verify Splunk is accessible: https://localhost:8000"
echo "  2. Install Salt master: saltServerInstall.sh"
echo "  3. Install Wazuh server"
echo "  4. Configure DNS server"
echo "  5. Run threat hunting tools carefully"
echo ""
echo "SERVICE VERIFICATION:"
echo "  # Splunk status"
echo "  /opt/splunk/bin/splunk status"
echo "  # Splunk Web"
echo "  curl -k https://localhost:8000"
echo ""
echo "========================================================"

exit 0
