#!/bin/bash
#
#  A script to automate a stepped Splunk upgrade during competition.
#  This path (9.1.x -> 9.4.x -> 10.0.x) is supported.
#   Don't ask me how bloody long it took to find the documentation on this. So. Much. Time. Wasted.
#
#
#  Samuel Brucker 2024-2026
#

# --- Version 1 (Intermediate) ---
# We must first upgrade to a 9.x version. We'll use 9.4.1.
SPLUNK_V9_VER="9.4.1"
SPLUNK_V9_BUILD="de415b3b9b32"
SPLUNK_V9_RPM="splunk-${SPLUNK_V9_VER}-${SPLUNK_V9_BUILD}.x86_64.rpm"
SPLUNK_V9_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_V9_VER}/linux/${SPLUNK_V9_RPM}"

# --- Version 2 (Final) ---
SPLUNK_V10_VER="10.0.1"
SPLUNK_V10_BUILD="ea5bfadeac3a"
SPLUNK_V10_RPM="splunk-${SPLUNK_V10_VER}-${SPLUNK_V10_BUILD}.x86_64.rpm"
SPLUNK_V10_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_V10_VER}/linux/${SPLUNK_V10_RPM}"


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

# Download 9.4.1
if ! wget -q --show-progress "$SPLUNK_V9_URL" -O "$SPLUNK_V9_RPM"; then
    echo "Splunk ${SPLUNK_V9_VER} failed to download"
    exit 1
fi

# Install 9.4.1
if ! rpm -Uhv "$SPLUNK_V9_RPM"; then
    echo "Upgrade to ${SPLUNK_V9_VER} failed"
    exit 1
fi

# Start Splunk to allow it to migrate to 9.4.1
echo "Starting Splunk to migrate to ${SPLUNK_V9_VER}..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes

echo "Migration to ${SPLUNK_V9_VER} complete. Stopping Splunk for next step."
"$SPLUNK_HOME/bin/splunk" stop
rm -f "$SPLUNK_V9_RPM"
echo "--- Step 1 Complete ---"


# -----------------------------------------------------------------
#  STEP 2: UPGRADE TO 10.0.1
# -----------------------------------------------------------------
echo ""
echo "--- Starting Step 2: Upgrading to ${SPLUNK_V10_VER} ---"

# Download 10.0.1
if ! wget -q --show-progress "$SPLUNK_V10_URL" -O "$SPLUNK_V10_RPM"; then
    echo "Splunk ${SPLUNK_V10_VER} failed to download"
    exit 1
fi

# Install 10.0.1 (using --nopre to skip package precheck)
if ! rpm -Uhv --nopre "$SPLUNK_V10_RPM"; then
    echo "Upgrade to ${SPLUNK_V10_VER} failed"
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

# Final Start
echo "Starting Splunk to complete migration to ${SPLUNK_V10_VER}..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes

# Clean up final package
rm -f "$SPLUNK_V10_RPM"

echo ""
echo "--- Stepped upgrade to ${SPLUNK_V10_VER} complete! ---"