#!/bin/bash
#
# AUTOMATED ROOTKIT DEFENSE & MONITORING
# 
# Actions:
# 1. Installs rkhunter and chkrootkit (Distro Agnostic).
# 2. Creates a custom logging directory for SIEM ingestion.
# 3. Creates a scanner wrapper that runs both tools.
# 4. Schedules the scanner to run every 15 minutes.
# 5. Alerts via 'wall' (broadcast) only if threats are found.

set -e

# --- Root Check ---
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Must run as root"
  exit 1
fi

# --- Variables & Setup ---
LOG_DIR="/var/log/syst"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/integrity_scan.log"
PRE_INSTALL_LOG="$LOG_DIR/pre_install_compromise.log"
CRON_JOB="/etc/cron.d/auto_rootkit_scan"
SCANNER_SCRIPT="/usr/local/bin/auto_scan_wrapper.sh"

echo ">>> [PHASE 1] Detecting Distro and Installing Tools..."

# --- Distro Detection & Installation ---
if command -v apt-get &> /dev/null; then
    echo "[+] Detected APT (Debian/Ubuntu-based)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y rkhunter chkrootkit -q

elif command -v dnf &> /dev/null; then
    echo "[+] Detected DNF (RHEL 8+/Fedora/Oracle)"
    # FIX: Fedora (Webmail) does not use EPEL. "|| true" prevents script death.
    dnf install -y epel-release || true
    dnf install -y rkhunter chkrootkit

elif command -v yum &> /dev/null; then
    echo "[+] Detected YUM (Legacy RHEL/CentOS)"
    yum install -y epel-release
    yum install -y rkhunter chkrootkit

else
    echo "!! ERROR: No supported package manager found. Manual install required. !!"
    exit 1
fi

echo "[*] Verifying system binary integrity via Package Manager..."

# FIX: Standardized log path to $PRE_INSTALL_LOG
if command -v rpm &> /dev/null; then
    # RHEL/Fedora/Oracle
    echo "Running RPM verification..."
    # We verify all files (-Va) and look for MD5/File Size mismatches in binary paths
    rpm -Va | grep -E '^..5' | grep -E '/bin/|/sbin/|/usr/lib/' > "$PRE_INSTALL_LOG" || true
    
elif command -v dpkg &> /dev/null; then
    # Debian/Ubuntu
    echo "Running DPKG verification..."
    dpkg --verify | grep -E '/bin/|/sbin/|/usr/lib/' > "$PRE_INSTALL_LOG" || true
fi

if [ -s "$PRE_INSTALL_LOG" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "CRITICAL WARNING: SYSTEM BINARIES DO NOT MATCH PACKAGE MANAGER!"
    echo "The system may ALREADY be compromised."
    echo "Check $PRE_INSTALL_LOG immediately."
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    # Active Defense: Wall this immediately
    echo "CRITICAL: binaries modified BEFORE install. Check $PRE_INSTALL_LOG" | wall
fi


# --- Configuration & Baselining ---
echo "[*] Baselining rkhunter properties..."
# We run a propupd to silence warnings about the current state of files.
# Assumption: The system is currently in the state you want to protect.
rkhunter --propupd --quiet

# --- Create the Scanner Wrapper Script ---
echo ">>> [PHASE 2] Creating Scan Logic..."

cat <<EOF > "$SCANNER_SCRIPT"
#!/bin/bash

# Define Log Path
LOG_TARGET="$LOG_FILE"
HOST_NAME=\$(hostname)
THREAT_DETECTED=0

# Temp file for this specific scan's findings
SCAN_TEMP=\$(mktemp)

echo "--- Scan initiated at \$(date) ---" > "\$SCAN_TEMP"

# 1. Run rkhunter (Warnings only)
# --rwo = report warnings only, --sk = skip keypress
RK_OUT=\$(rkhunter --check --sk --rwo --nocolors 2>/dev/null)

if [ -n "\$RK_OUT" ]; then
    THREAT_DETECTED=1
    echo "[!] RKHUNTER WARNINGS:" >> "\$SCAN_TEMP"
    echo "\$RK_OUT" >> "\$SCAN_TEMP"
    echo "" >> "\$SCAN_TEMP"
fi

# 2. Run chkrootkit (Infected only)
CHK_OUT=\$(chkrootkit -q | grep "INFECTED")

if [ -n "\$CHK_OUT" ]; then
    THREAT_DETECTED=1
    echo "[!] CHKROOTKIT FINDINGS:" >> "\$SCAN_TEMP"
    echo "\$CHK_OUT" >> "\$SCAN_TEMP"
    echo "" >> "\$SCAN_TEMP"
fi

# 3. Decision Logic
if [ "\$THREAT_DETECTED" -eq 1 ]; then
    # A. Append findings to the main log for the SIEM
    cat "\$SCAN_TEMP" >> "\$LOG_TARGET"
    
    # B. Send ONE broadcast message to terminals
    echo "SECURITY ALERT: Rootkit/Anomaly detected on \$HOST_NAME. Check \$LOG_TARGET immediately." | wall
else
    # Heartbeat for SIEM (optional, helps verify agent is alive)
    # echo "Scan clean" >> "\$LOG_TARGET"
    :
fi

# Cleanup
rm -f "\$SCAN_TEMP"
EOF

chmod +x "$SCANNER_SCRIPT"
chmod 700 "$SCANNER_SCRIPT"

echo ">>> [PHASE 3] Scheduling Persistence..."
# Runs every 15 minutes
echo "*/15 * * * * root $SCANNER_SCRIPT" > "$CRON_JOB"
chmod 644 "$CRON_JOB"

echo ">>> [PHASE 4] Execution"
echo "[+] Initial scan running now (backgrounded)..."
# Run in background so the install script finishes quickly
"$SCANNER_SCRIPT" &

echo "---[ DEPLOYMENT COMPLETE ]---"
echo "Logs: $LOG_FILE"
echo "Schedule: Every 15 minutes"
echo "Alerts: Wall message triggers ONLY on detection."