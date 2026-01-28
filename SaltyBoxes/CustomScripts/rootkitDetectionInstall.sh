#!/bin/bash
#
# AUTOMATED ROOTKIT DEFENSE & MONITORING (SILENT MODE)
#
# Actions:
# 1. Installs rkhunter and chkrootkit (Distro Agnostic).
# 2. Creates a custom logging directory for SIEM ingestion.
# 3. Creates a scanner wrapper that runs both tools + LD_PRELOAD check.
# 4. Schedules the scanner to run every 15 minutes.
# 5. NO WALL MESSAGES - Silent logging only.
#
# LD_PRELOAD Detection:
# - Checks /etc/ld.so.preload for malicious entries
# - Uses chroot technique to bypass userspace rootkit hooks
# - Scans process environments for LD_PRELOAD variables

set -e

# --- Root Check ---
if [ "$EUID" -ne 0 ]; then
  echo "!! ERROR: Must run as root !!"
  exit 1
fi

# --- Variables & Setup ---
LOG_DIR="/var/log/syst"
# Create directory FIRST so early logs don't fail
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

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
    # Fedora does not use EPEL. "|| true" prevents script death.
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

# Standardized log path to $PRE_INSTALL_LOG
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

# 3. LD_PRELOAD Rootkit Check (Chroot Technique)
# This bypasses potential LD_PRELOAD hooks by using a minimal chroot environment

# Direct check of ld.so.preload
if [ -s /etc/ld.so.preload ]; then
    THREAT_DETECTED=1
    echo "[!] LD_PRELOAD ROOTKIT - /etc/ld.so.preload contains:" >> "\$SCAN_TEMP"
    cat /etc/ld.so.preload >> "\$SCAN_TEMP"
    echo "" >> "\$SCAN_TEMP"
fi

# Chroot-based verification (bypasses userspace rootkits)
CHROOT_DIR="/tmp/.rkcheck_\$\$"
if mkdir -p "\$CHROOT_DIR"/{bin,lib,lib64,etc} 2>/dev/null; then
    # Copy minimal binaries and libraries
    cp /bin/cat "\$CHROOT_DIR/bin/" 2>/dev/null

    # Copy required libraries for cat
    for lib in \$(ldd /bin/cat 2>/dev/null | grep -v dynamic | awk '{print \$3}' | grep -v "^\$"); do
        [ -f "\$lib" ] && cp "\$lib" "\$CHROOT_DIR/lib/" 2>/dev/null
    done
    cp /lib64/ld-linux-x86-64.so.2 "\$CHROOT_DIR/lib64/" 2>/dev/null
    cp /lib/ld-linux*.so* "\$CHROOT_DIR/lib/" 2>/dev/null

    # Copy ld.so.preload for comparison
    cp /etc/ld.so.preload "\$CHROOT_DIR/etc/" 2>/dev/null

    # Check from inside chroot (bypasses LD_PRELOAD hooks)
    CHROOT_RESULT=\$(chroot "\$CHROOT_DIR" /bin/cat /etc/ld.so.preload 2>/dev/null)
    if [ -n "\$CHROOT_RESULT" ]; then
        THREAT_DETECTED=1
        echo "[!] LD_PRELOAD ROOTKIT (CHROOT VERIFIED):" >> "\$SCAN_TEMP"
        echo "\$CHROOT_RESULT" >> "\$SCAN_TEMP"
        echo "" >> "\$SCAN_TEMP"
    fi

    # Cleanup chroot environment
    rm -rf "\$CHROOT_DIR" 2>/dev/null
fi

# Check LD_PRELOAD environment variable in running processes
LD_ENV_CHECK=\$(grep -r "LD_PRELOAD" /proc/*/environ 2>/dev/null | grep -v "grep" | head -5)
if [ -n "\$LD_ENV_CHECK" ]; then
    THREAT_DETECTED=1
    echo "[!] LD_PRELOAD IN PROCESS ENVIRONMENT:" >> "\$SCAN_TEMP"
    echo "\$LD_ENV_CHECK" >> "\$SCAN_TEMP"
    echo "" >> "\$SCAN_TEMP"
fi

# 4. Decision Logic
if [ "\$THREAT_DETECTED" -eq 1 ]; then
    # Append findings to the main log for the SIEM
    cat "\$SCAN_TEMP" >> "\$LOG_TARGET"
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
echo "Silent Mode: Active (No terminal broadcasts)"