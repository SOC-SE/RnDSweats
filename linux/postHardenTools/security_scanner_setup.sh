#!/bin/bash
# ==============================================================================
# Script Name: security_scanner_setup.sh
# Description: Installs and runs rkhunter, chkrootkit, ClamAV, and YARA,
#              then produces a consolidated security report.
# Author: CCDC Team
# Date: 2025-2026
# Version: 3.0
#
# Usage:
#   sudo ./security_scanner_setup.sh
#
# What It Does:
#   1. Installs rkhunter, chkrootkit, clamav, yara if not present
#   2. Updates signatures/databases
#   3. Runs all scanners
#   4. Produces a consolidated report at /var/log/syst/security_scan_<date>.log
#
# Supported Systems:
#   - Ubuntu/Debian
#   - Fedora/RHEL/Oracle/Rocky
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   3 - Not root
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
LOG_DIR="/var/log/syst"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$LOG_DIR/security_scan_$TIMESTAMP.log"
SCAN_DIRS="/tmp /var/tmp /dev/shm /home /var/www /etc /root"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${GREEN}[INFO]${NC} $1"; echo "[INFO] $1" >> "$REPORT_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; echo "[WARN] $1" >> "$REPORT_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; echo "[ERROR] $1" >> "$REPORT_FILE"; }

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 3
fi

mkdir -p "$LOG_DIR"

echo "========================================" | tee "$REPORT_FILE"
echo "CONSOLIDATED SECURITY SCAN REPORT" | tee -a "$REPORT_FILE"
echo "Host: $(hostname)" | tee -a "$REPORT_FILE"
echo "Date: $(date)" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- Detect distro ---
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="$ID"
else
    DISTRO="unknown"
fi

# --- Install tools ---
log "Installing security scanning tools..."

install_pkg() {
    local pkg="$1"
    case "$DISTRO" in
        ubuntu|debian)
            dpkg -s "$pkg" &>/dev/null || apt-get install -y "$pkg" 2>/dev/null
            ;;
        fedora)
            rpm -q "$pkg" &>/dev/null || dnf install -y "$pkg" 2>/dev/null
            ;;
        ol|rhel|centos|rocky|almalinux|oracle)
            rpm -q "$pkg" &>/dev/null || {
                rpm -q epel-release &>/dev/null || yum install -y epel-release 2>/dev/null
                yum install -y "$pkg" 2>/dev/null || dnf install -y "$pkg" 2>/dev/null
            }
            ;;
    esac
}

# Install rkhunter
if ! command -v rkhunter &>/dev/null; then
    log "Installing rkhunter..."
    install_pkg rkhunter
fi

# Install chkrootkit
if ! command -v chkrootkit &>/dev/null; then
    log "Installing chkrootkit..."
    install_pkg chkrootkit
fi

# Install ClamAV
if ! command -v clamscan &>/dev/null; then
    log "Installing ClamAV..."
    case "$DISTRO" in
        ubuntu|debian)
            apt-get install -y clamav clamav-daemon 2>/dev/null
            ;;
        fedora)
            dnf install -y clamav clamd clamav-update 2>/dev/null
            ;;
        ol|rhel|centos|rocky|almalinux|oracle)
            rpm -q epel-release &>/dev/null || yum install -y epel-release
            yum install -y clamav clamd clamav-update 2>/dev/null
            ;;
    esac
fi

# Install YARA
if ! command -v yara &>/dev/null; then
    log "Installing YARA..."
    install_pkg yara
fi

# --- Update signatures ---
log "Updating virus/malware signatures..."

if command -v freshclam &>/dev/null; then
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam 2>/dev/null || warn "freshclam update failed (may be rate-limited)"
    systemctl start clamav-freshclam 2>/dev/null || true
fi

if command -v rkhunter &>/dev/null; then
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true
fi

# --- Run Scans ---

# 1. rkhunter
echo "" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "RKHUNTER SCAN" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

if command -v rkhunter &>/dev/null; then
    log "Running rkhunter..."
    rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | tee -a "$REPORT_FILE"
    log "rkhunter scan complete"
else
    warn "rkhunter not available"
fi

# 2. chkrootkit
echo "" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "CHKROOTKIT SCAN" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

if command -v chkrootkit &>/dev/null; then
    log "Running chkrootkit..."
    chkrootkit 2>/dev/null | grep -v "not found\|not infected\|nothing found\|not tested" | tee -a "$REPORT_FILE"
    log "chkrootkit scan complete"
else
    warn "chkrootkit not available"
fi

# 3. ClamAV
echo "" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "CLAMAV SCAN" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

if command -v clamscan &>/dev/null; then
    log "Running ClamAV scan on key directories..."
    for dir in $SCAN_DIRS; do
        if [[ -d "$dir" ]]; then
            echo "--- Scanning $dir ---" >> "$REPORT_FILE"
            clamscan -r --no-summary --infected "$dir" 2>/dev/null >> "$REPORT_FILE" || true
        fi
    done
    # Summary
    echo "--- ClamAV Summary ---" >> "$REPORT_FILE"
    clamscan -r $SCAN_DIRS 2>/dev/null | tail -10 | tee -a "$REPORT_FILE"
    log "ClamAV scan complete"
else
    warn "clamscan not available"
fi

# 4. YARA (if rules exist)
echo "" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "YARA SCAN" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

if command -v yara &>/dev/null; then
    # Look for YARA rules in common locations
    YARA_RULES=""
    for rules_dir in /etc/yara /opt/yara-rules /usr/share/yara "$SCRIPT_DIR/../Tools/Yara"; do
        if [[ -d "$rules_dir" ]]; then
            YARA_RULES=$(find "$rules_dir" -name "*.yar" -o -name "*.yara" 2>/dev/null | head -20)
            break
        fi
    done

    if [[ -n "$YARA_RULES" ]]; then
        log "Running YARA scan with detected rules..."
        for rule in $YARA_RULES; do
            echo "--- Rule: $(basename "$rule") ---" >> "$REPORT_FILE"
            for dir in /tmp /var/tmp /dev/shm; do
                [[ -d "$dir" ]] && yara -r "$rule" "$dir" 2>/dev/null >> "$REPORT_FILE" || true
            done
        done
        log "YARA scan complete"
    else
        log "No YARA rules found. Install rules to /etc/yara or Tools/Yara/ for scanning."
        echo "No YARA rules found." >> "$REPORT_FILE"
    fi
else
    warn "yara not available"
fi

# 5. Quick system integrity checks
echo "" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "SYSTEM INTEGRITY CHECKS" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

log "Running system integrity checks..."

echo "--- Deleted executables still running ---" >> "$REPORT_FILE"
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' >> "$REPORT_FILE" 2>/dev/null || echo "None found" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "--- Processes from /tmp or /dev/shm ---" >> "$REPORT_FILE"
ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm|/var/tmp' >> "$REPORT_FILE" 2>/dev/null || echo "None found" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "--- Promiscuous interfaces (sniffing) ---" >> "$REPORT_FILE"
ip link 2>/dev/null | grep PROMISC >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "--- Hidden files in /tmp /var/tmp /dev/shm ---" >> "$REPORT_FILE"
find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "--- World-writable files in /etc ---" >> "$REPORT_FILE"
find /etc -type f -perm -002 2>/dev/null >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"

log "System integrity checks complete"

# --- Summary ---
echo "" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "SCAN COMPLETE" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Full report: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

exit 0
