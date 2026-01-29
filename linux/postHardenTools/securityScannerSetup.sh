#!/bin/bash
# ==============================================================================
# Script Name: securityScannerSetup.sh
# Description: Installs and runs security scanning tools, optionally with
#              scheduled or real-time malware monitoring via LMD + ClamAV.
#
# Usage:
#   sudo ./securityScannerSetup.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -m, --mode       Scan mode: 'scan' (default), 'cron', or 'realtime'
#   -i, --interval   Cron interval in minutes (default: 15, only with --mode cron)
#
# Modes:
#   scan      - Install tools, run all scanners, produce consolidated report (default)
#   cron      - Install LMD + ClamAV with scheduled scanning every N minutes
#   realtime  - Install LMD + ClamAV with inotify-based real-time monitoring
#
# Scanners (scan mode):
#   - rkhunter      (rootkit detection)
#   - chkrootkit    (rootkit detection)
#   - ClamAV        (antivirus)
#   - YARA          (pattern-based malware detection)
#   - System integrity checks
#
# Supported Systems:
#   - Ubuntu/Debian
#   - Fedora/RHEL/Oracle/Rocky/Alma
#
# WARNING: Real-time mode is resource intensive. Too much for most 2GB systems.
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   3 - Not root
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
MODE="scan"
CRON_INTERVAL=15
LOG_DIR="/var/log/syst"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$LOG_DIR/security_scan_$TIMESTAMP.log"
SCAN_DIRS="/tmp /var/tmp /dev/shm /home /var/www /etc /root"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -40 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log()   { echo -e "${GREEN}[INFO]${NC} $1"; [[ "$MODE" == "scan" ]] && echo "[INFO] $1" >> "$REPORT_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; [[ "$MODE" == "scan" ]] && echo "[WARN] $1" >> "$REPORT_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
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
            if [[ "$MODE" != "scan" && "$MODE" != "cron" && "$MODE" != "realtime" ]]; then
                error "Invalid mode: $MODE (use 'scan', 'cron', or 'realtime')"
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
mkdir -p "$LOG_DIR"

# --- Detect distro ---
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="$ID"
else
    DISTRO="unknown"
fi

# --- Package installer helper ---
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

# ==============================================================================
# MODE: scan — Install tools, run all scanners, produce report
# ==============================================================================
if [[ "$MODE" == "scan" ]]; then

    echo "========================================" | tee "$REPORT_FILE"
    echo "CONSOLIDATED SECURITY SCAN REPORT" | tee -a "$REPORT_FILE"
    echo "Host: $(hostname)" | tee -a "$REPORT_FILE"
    echo "Date: $(date)" | tee -a "$REPORT_FILE"
    echo "========================================" | tee -a "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # --- Install tools ---
    log "Installing security scanning tools..."

    # rkhunter
    if ! command -v rkhunter &>/dev/null; then
        log "Installing rkhunter..."
        install_pkg rkhunter
    fi

    # chkrootkit
    if ! command -v chkrootkit &>/dev/null; then
        log "Installing chkrootkit..."
        install_pkg chkrootkit
    fi

    # ClamAV
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

    # YARA
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
        echo "--- ClamAV Results ---" >> "$REPORT_FILE"
        clamscan -r --infected $SCAN_DIRS 2>/dev/null | tee -a "$REPORT_FILE"
        log "ClamAV scan complete"
    else
        warn "clamscan not available"
    fi

    # 4. YARA
    echo "" >> "$REPORT_FILE"
    echo "========================================" >> "$REPORT_FILE"
    echo "YARA SCAN" >> "$REPORT_FILE"
    echo "========================================" >> "$REPORT_FILE"

    if command -v yara &>/dev/null; then
        YARA_RULES=""
        for rules_dir in /etc/yara /opt/yara-rules /usr/share/yara; do
            if [[ -d "$rules_dir" ]]; then
                YARA_RULES="$YARA_RULES $(find "$rules_dir" -name "*.yar" -o -name "*.yara" 2>/dev/null | head -20)"
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
            log "No YARA rules found. Install rules to /etc/yara or /opt/yara-rules/ for scanning."
            echo "No YARA rules found." >> "$REPORT_FILE"
        fi
    else
        warn "yara not available"
    fi

    # 5. System integrity checks
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

    # Summary
    echo "" | tee -a "$REPORT_FILE"
    echo "========================================" | tee -a "$REPORT_FILE"
    echo "SCAN COMPLETE" | tee -a "$REPORT_FILE"
    echo "========================================" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "Full report: $REPORT_FILE" | tee -a "$REPORT_FILE"

    exit 0
fi

# ==============================================================================
# MODE: cron / realtime — Install LMD + ClamAV with scheduled or live monitoring
# ==============================================================================

echo "========================================"
echo "Linux AV Installation (LMD + ClamAV)"
echo "Mode: $MODE"
[[ "$MODE" == "cron" ]] && echo "Interval: $CRON_INTERVAL minutes"
echo "========================================"
echo ""

# Detect distro for package management
if [ -f /etc/debian_version ]; then
    PKG_DISTRO="debian"
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
    PKG_DISTRO="redhat"
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

# Define scan directories
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

if [ "$PKG_DISTRO" == "redhat" ]; then
    $PACKAGE_MANAGER install -y $EPEL_PACKAGE
    $PACKAGE_MANAGER update -y
    $PACKAGE_MANAGER install -y $INSTALL_PACKAGES

    sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
    [[ "$MODE" == "realtime" ]] && sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf 2>/dev/null || true

    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true
    log "Downloading virus definitions..."
    freshclam || warn "freshclam update failed (rate limiting). Continuing..."

    systemctl enable --now "$FRESHCLAM_SERVICE"
    [[ "$MODE" == "realtime" ]] && systemctl enable --now "$CLAMAV_DAEMON_SERVICE"

elif [ "$PKG_DISTRO" == "debian" ]; then
    $PACKAGE_MANAGER update -y
    $PACKAGE_MANAGER install -y $INSTALL_PACKAGES

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
# LMD scheduled scan - runs every $CRON_INTERVAL minutes (flock prevents stacking)
*/$CRON_INTERVAL * * * * root /usr/bin/flock -xn /tmp/maldet.lock /usr/local/sbin/maldet -b -a ${SCAN_PATH_STRING} > /dev/null 2>&1
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
