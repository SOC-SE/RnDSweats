#!/bin/bash
#
#  A script to automate a 3-step Splunk upgrade during competition.
#  This path (9.1.x -> 9.4.1 -> 10.0.0 -> 10.0.1) is supported.
#
#  Samuel Brucker 2024-2025

# --- Version 1 (Intermediate) ---
SPLUNK_V9_VER="9.4.1"
SPLUNK_V9_BUILD="e3bdab203ac8"
SPLUNK_V9_RPM="splunk-${SPLUNK_V9_VER}-${SPLUNK_V9_BUILD}.x86_64.rpm"
SPLUNK_V9_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_V9_VER}/linux/${SPLUNK_V9_RPM}"

# --- Version 2 (Intermediate) ---
SPLUNK_V10_0_VER="10.0.0"
SPLUNK_V10_0_BUILD="e8eb0c4654f8"
SPLUNK_V10_0_RPM="splunk-${SPLUNK_V10_0_VER}-${SPLUNK_V10_0_BUILD}.x86_64.rpm"
SPLUNK_V10_0_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_V10_0_VER}/linux/${SPLUNK_V10_0_RPM}"

# --- Version 3 (Final) ---
SPLUNK_V10_1_VER="10.0.1"
SPLUNK_V10_1_BUILD="ea5bfadeac3a"
SPLUNK_V10_1_RPM="splunk-${SPLUNK_V10_1_VER}-${SPLUNK_V10_1_BUILD}.x86_64.rpm"
SPLUNK_V10_1_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_V10_1_VER}/linux/${SPLUNK_V10_1_RPM}"


# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo privileges"
    exit 1
fi

# Set Splunk home path
SPLUNK_HOME=/opt/splunk

# Stop Splunk first
echo "Stopping Splunk..."
"$SPLUNK_HOME/bin/splunk" stop

# Backup current installation (config ONLY)
echo "Backing up Splunk /etc configuration..."
BACKUP_DIR="/tmp/splunk_backup_pre-update_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -rp "$SPLUNK_HOME/etc" "$BACKUP_DIR/"


# -----------------------------------------------------------------
#  STEP 1: UPGRADE TO 9.4.1
# -----------------------------------------------------------------
echo ""
echo "--- Starting Step 1: Upgrading to ${SPLUNK_V9_VER} ---"
if ! wget -q --show-progress "$SPLUNK_V9_URL" -O "$SPLUNK_V9_RPM"; then
    echo "Splunk ${SPLUNK_V9_VER} failed to download"
    exit 1
fi

# No --nopre needed for this jump
if ! rpm -Uhv "$SPLUNK_V9_RPM"; then
    echo "Upgrade to ${SPLUNK_V9_VER} failed"
    exit 1
fi

echo "Starting Splunk to migrate to ${SPLUNK_V9_VER}..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes
echo "Migration to ${SPLUNK_V9_VER} complete. Stopping Splunk for next step."
"$SPLUNK_HOME/bin/splunk" stop
rm -f "$SPLUNK_V9_RPM"
echo "--- Step 1 Complete ---"


# -----------------------------------------------------------------
#  STEP 2: UPGRADE TO 10.0.0
# -----------------------------------------------------------------
echo ""
echo "--- Starting Step 2: Upgrading to ${SPLUNK_V10_0_VER} ---"
if ! wget -q --show-progress "$SPLUNK_V10_0_URL" -O "$SPLUNK_V10_0_RPM"; then
    echo "Splunk ${SPLUNK_V10_0_VER} failed to download"
    exit 1
fi

# Use --nopre to skip buggy package precheck
if ! rpm -Uhv --nopre "$SPLUNK_V10_0_RPM"; then
    echo "Upgrade to ${SPLUNK_V10_0_VER} failed"
    exit 1
fi

# --- Apply KV Store Workaround ---
# Manually create the version file to trick the 'splunk start' precheck
echo "Applying workaround: Manually creating KVStore version file..."
VERSION_DIR="$SPLUNK_HOME/var/run/splunk/kvstore_upgrade"
VERSION_FILE="$VERSION_DIR/versionFile42"
mkdir -p "$VERSION_DIR"
touch "$VERSION_FILE"
# Ensure the new files are owned by the splunk user, not root
chown -R $(stat -c '%U:%G' "$SPLUNK_HOME") "$VERSION_DIR"
echo "Workaround file created."
# --- End Workaround ---

echo "Starting Splunk to migrate to ${SPLUNK_V10_0_VER}..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes
echo "Migration to ${SPLUNK_V10_0_VER} complete. Stopping Splunk for next step."
"$SPLUNK_HOME/bin/splunk" stop
rm -f "$SPLUNK_V10_0_RPM"
echo "--- Step 2 Complete ---"


# -----------------------------------------------------------------
#  STEP 3: UPGRADE TO 10.0.1
# -----------------------------------------------------------------
echo ""
echo "--- Starting Step 3: Upgrading to ${SPLUNK_V10_1_VER} ---"
if ! wget -q --show-progress "$SPLUNK_V10_1_URL" -O "$SPLUNK_V10_1_RPM"; then
    echo "Splunk ${SPLUNK_V10_1_VER} failed to download"
    exit 1
fi

# This is a minor patch, so no prechecks or workarounds should be needed.
if ! rpm -Uhv "$SPLUNK_V10_1_RPM"; then
    echo "Upgrade to ${SPLUNK_V10_1_VER} failed"
    exit 1
fi

echo "Starting Splunk to complete migration to ${SPLUNK_V10_1_VER}..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes
rm -f "$SPLUNK_V10_1_RPM"
echo ""
echo "--- Stepped upgrade to ${SPLUNK_V10_1_VER} complete! ---"