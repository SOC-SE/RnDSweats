#!/bin/bash
# ==============================================================================
# Script Name: linuxAVInstall.sh
# Description: LMD & ClamAV installation with scheduled or real-time scanning
#              Combines cron-based and inotify-based monitoring modes
# Author: CCDC Team (Samuel Brucker 2025-2026)
# Date: 2025-2026
# Version: 2.0
#
# Usage:
#   ./linuxAVInstall.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -m, --mode       Scan mode: 'cron' (default) or 'realtime'
#   -i, --interval   Cron interval in minutes (default: 15)
#
# Modes:
#   cron      - Scheduled scanning every N minutes (default, lighter resource usage)
#   realtime  - inotify-based real-time file monitoring (heavier, requires clamd)
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   3 - Permission denied
#
# ==============================================================================

set -euo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
MODE="cron"
CRON_INTERVAL=15

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -35 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root"
        exit 3
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -m|--mode)
            MODE="$2"
            if [[ "$MODE" != "cron" && "$MODE" != "realtime" ]]; then
                error "Invalid mode: $MODE (use 'cron' or 'realtime')"
                exit 1
            fi
            shift 2
            ;;
        -i|--interval)
            CRON_INTERVAL="$2"
            shift 2
            ;;
        *)
            error "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main ---
check_root

echo "========================================"
echo "Linux AV Installation (LMD + ClamAV)"
echo "Mode: $MODE"
[[ "$MODE" == "cron" ]] && echo "Interval: $CRON_INTERVAL minutes"
echo "========================================"
echo ""

# Detect Linux Distribution
log "Detecting Linux distribution..."
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
    PACKAGE_MANAGER="apt-get"
    FRESHCLAM_SERVICE="clamav-freshclam"
    CLAMAV_DAEMON_SERVICE="clamav-daemon"
    if [[ "$MODE" == "realtime" ]]; then
        INSTALL_PACKAGES="clamav clamav-daemon clamav-freshclam inotify-tools"
    else
        INSTALL_PACKAGES="clamav clamav-freshclam inotify-tools"
    fi
    log "Debian-based system detected"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    else
        PACKAGE_MANAGER="yum"
    fi
    FRESHCLAM_SERVICE="clamav-freshclam"
    CLAMAV_DAEMON_SERVICE="clamd@scan"
    EPEL_PACKAGE="epel-release"
    if [[ "$MODE" == "realtime" ]]; then
        INSTALL_PACKAGES="clamav-server clamav-data clamav-update inotify-tools"
    else
        INSTALL_PACKAGES="clamav clamav-update inotify-tools"
    fi
    log "Red Hat-based system detected"
else
    error "Unsupported Linux distribution"
    exit 1
fi

# Define directories for scanning
log "Defining directories for scanning..."
SCAN_LIST_ARRAY=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/home" "/etc/systemd/system" "/lib/systemd/system" "/root" "/var/fcgi_ipc")

FINAL_SCAN_PATHS_ARRAY=()
for path in "${SCAN_LIST_ARRAY[@]}"; do
    if [ -d "$path" ]; then
        FINAL_SCAN_PATHS_ARRAY+=("$path")
    fi
done

SCAN_PATH_STRING=$(IFS=,; echo "${FINAL_SCAN_PATHS_ARRAY[*]}")

if [ -z "$SCAN_PATH_STRING" ]; then
    error "No valid directories found to scan"
    exit 1
fi

log "Paths to scan:"
printf "  %s\n" "${FINAL_SCAN_PATHS_ARRAY[@]}"
echo ""

# Install ClamAV
log "Installing ClamAV and dependencies..."

if [ "$DISTRO" == "redhat" ]; then
    $PACKAGE_MANAGER install -y $EPEL_PACKAGE
    $PACKAGE_MANAGER update -y
    $PACKAGE_MANAGER install -y $INSTALL_PACKAGES

    # Config fixes
    sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
    [[ "$MODE" == "realtime" ]] && sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf 2>/dev/null || true

    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true
    log "Downloading virus definitions..."
    freshclam || warn "freshclam update failed (rate limiting). Continuing..."

    systemctl enable --now "$FRESHCLAM_SERVICE"
    [[ "$MODE" == "realtime" ]] && systemctl enable --now "$CLAMAV_DAEMON_SERVICE"

elif [ "$DISTRO" == "debian" ]; then
    $PACKAGE_MANAGER update -y
    $PACKAGE_MANAGER install -y $INSTALL_PACKAGES

    # Config fixes
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true
    if [[ "$MODE" == "realtime" ]]; then
        sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf 2>/dev/null || true
        sed -i 's~^#LocalSocket /var/run/clamav/clamd.sock~LocalSocket /var/run/clamav/clamd.sock~' /etc/clamav/clamd.conf 2>/dev/null || true
    fi

    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true
    log "Downloading virus definitions..."
    freshclam || warn "freshclam update failed (rate limiting). Continuing..."

    systemctl enable --now "$FRESHCLAM_SERVICE"
    [[ "$MODE" == "realtime" ]] && systemctl enable --now "$CLAMAV_DAEMON_SERVICE"
fi

[[ "$MODE" == "realtime" ]] && sleep 5

log "ClamAV installation complete"

# Install LMD
log "Installing Linux Malware Detect (LMD)..."
cd /tmp
rm -f maldetect-current.tar.gz
rm -rf maldetect-*/

wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xzf maldetect-current.tar.gz

LMD_DIR=$(find . -maxdepth 1 -type d -name "maldetect-*" | head -1)
if [ -z "$LMD_DIR" ]; then
    error "Failed to find LMD installation directory"
    exit 1
fi

cd "$LMD_DIR"
./install.sh > /dev/null 2>&1
log "LMD installation complete"

# Configure LMD
log "Configuring LMD..."
CONFIG_FILE="/usr/local/maldetect/conf.maldet"

sed -i 's/^email_alert = .*/email_alert = "0"/' "$CONFIG_FILE"
sed -i 's/^quarantine_hits = "0"/quarantine_hits = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_clamscan = "0"/scan_clamscan = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_ignore_root = "1"/scan_ignore_root = "0"/' "$CONFIG_FILE"

if [[ "$MODE" == "realtime" ]]; then
    sed -i 's~^#scan_clamd_socket = ""~scan_clamd_socket = "/var/run/clamav/clamd.sock"~' "$CONFIG_FILE"
else
    sed -i 's~^scan_clamd_socket = "/var/run/clamav/clamd.sock"~#scan_clamd_socket = "/var/run/clamav/clamd.sock"~' "$CONFIG_FILE"
fi

log "LMD configured: quarantine enabled, ClamAV integration enabled"

# Update LMD signatures
log "Updating LMD signatures..."
maldet -u > /dev/null 2>&1 || true
maldet -d > /dev/null 2>&1 || true

# Set up scanning mode
if [[ "$MODE" == "cron" ]]; then
    log "Setting up cron-based scanning..."
    CRON_FILE="/etc/cron.d/maldet_scheduled_scan"

    cat > "$CRON_FILE" << EOF
# LMD scheduled scan - runs every $CRON_INTERVAL minutes
*/$CRON_INTERVAL * * * * root /usr/local/sbin/maldet -b -a ${SCAN_PATH_STRING} > /dev/null 2>&1
EOF

    chmod 0644 "$CRON_FILE"
    log "Cron job created: scanning every $CRON_INTERVAL minutes"

else
    log "Starting real-time monitoring..."
    maldet --monitor "$SCAN_PATH_STRING"
    log "Real-time monitoring started"
fi

# Summary
echo ""
echo "========================================"
echo "INSTALLATION COMPLETE"
echo "========================================"
echo ""
echo "Mode: $MODE"
if [[ "$MODE" == "cron" ]]; then
    echo "Scan interval: Every $CRON_INTERVAL minutes"
    echo "Cron file: /etc/cron.d/maldet_scheduled_scan"
else
    echo "Real-time monitoring active on:"
    printf "  %s\n" "${FINAL_SCAN_PATHS_ARRAY[@]}"
fi
echo ""
echo "Detected malware will be automatically quarantined."
echo ""
echo "Useful commands:"
echo "  View event log:  cat /usr/local/maldetect/logs/event_log"
echo "  View reports:    ls /usr/local/maldetect/sess/"
echo "  Manual scan:     maldet -a /path/to/scan"
echo "  View quarantine: maldet -l"
echo "========================================"

exit 0
