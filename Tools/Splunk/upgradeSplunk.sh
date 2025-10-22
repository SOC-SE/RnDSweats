#!/bin/bash
#
#  A script to automate a 3-step Splunk upgrade during competition.
#  This script is interactive and resumable.
#
#  Samuel Brucker 2024-2025

# --- Version 1 (Intermediate) ---
SPLUNK_V9_VER="9.4.1"
SPLUNK_V9_BUILD="de415b3b9b32"
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
SPLUNK_BIN="$SPLUNK_HOME/bin/splunk"

# -----------------------------------------------------------------
#  USER PROMPT
# -----------------------------------------------------------------
echo "This script can perform up to 3 upgrade steps:"
echo "   1. Upgrade to ${SPLUNK_V9_VER}"
echo "   2. Upgrade to ${SPLUNK_V10_0_VER}"
echo "   3. Upgrade to ${SPLUNK_V10_1_VER}"
echo ""
read -p "How many upgrade steps do you want to perform? (1, 2, or 3): " num_upgrades

# Validate input
if [[ ! "$num_upgrades" =~ ^[1-3]$ ]]; then
    echo "Error: Invalid input. Please enter 1, 2, or 3."
    exit 1
fi

# -----------------------------------------------------------------
#  INITIAL CHECK
# -----------------------------------------------------------------
# Check if we're already on the final version
if $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V10_1_VER"; then
    echo "Splunk is already at the final version (${SPLUNK_V10_1_VER}). Nothing to do."
    exit 0
fi

# If not, stop Splunk to begin
echo "Stopping Splunk to begin upgrade..."
"$SPLUNK_HOME/bin/splunk" stop

# Backup current installation (config ONLY)
echo "Backing up Splunk /etc configuration..."
BACKUP_DIR="/tmp/splunk_backup_pre-update_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -rp "$SPLUNK_HOME/etc" "$BACKUP_DIR/"


# -----------------------------------------------------------------
#  STEP 1: UPGRADE TO 9.4.1
# -----------------------------------------------------------------
if [ "$num_upgrades" -ge 1 ]; then
    # Idempotency check
    if $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V9_VER" || \
       $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V10_0_VER" || \
       $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V10_1_VER"; then
        echo "Already on ${SPLUNK_V9_VER} or newer. Skipping Step 1."
    else
        echo ""
        echo "--- Starting Step 1: Upgrading to ${SPLUNK_V9_VER} ---"
        if ! wget -q --show-progress "$SPLUNK_V9_URL" -O "$SPLUNK_V9_RPM"; then
            echo "Splunk ${SPLUNK_V9_VER} failed to download"
            exit 1
        fi

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
    fi
fi


# -----------------------------------------------------------------
#  STEP 2: UPGRADE TO 10.0.0
# -----------------------------------------------------------------
if [ "$num_upgrades" -ge 2 ]; then
    # Idempotency check
    if $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V10_0_VER" || \
       $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V10_1_VER"; then
        echo "Already on ${SPLUNK_V10_0_VER} or newer. Skipping Step 2."
    else
        echo ""
        echo "--- Starting Step 2: Upgrading to ${SPLUNK_V10_0_VER} ---"
        if ! wget -q --show-progress "$SPLUNK_V10_0_URL" -O "$SPLUNK_V10_0_RPM"; then
            echo "Splunk ${SPLUNK_V10_0_VER} failed to download"
            exit 1
        fi

        if ! rpm -Uhv --nopre "$SPLUNK_V10_0_RPM"; then
            echo "Upgrade to ${SPLUNK_V10_0_VER} failed"
            exit 1
        fi

        # --- Apply KV Store Workaround ---
        echo "Applying workaround: Manually creating KVStore version file..."
        VERSION_DIR="$SPLUNK_HOME/var/run/splunk/kvstore_upgrade"
        VERSION_FILE="$VERSION_DIR/versionFile42"
        mkdir -p "$VERSION_DIR"
        touch "$VERSION_FILE"
        chown -R $(stat -c '%U:%G' "$SPLUNK_HOME") "$VERSION_DIR"
        echo "Workaround file created."
        # --- End Workaround ---

        echo "Starting Splunk to migrate to ${SPLUNK_V10_0_VER}..."
        "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes
        echo "Migration to ${SPLUNK_V10_0_VER} complete. Stopping Splunk for next step."
        "$SPLUNK_HOME/bin/splunk" stop
        rm -f "$SPLUNK_V10_0_RPM"
        echo "--- Step 2 Complete ---"
    fi
fi


# -----------------------------------------------------------------
#  STEP 3: UPGRADE TO 10.0.1
# -----------------------------------------------------------------
if [ "$num_upgrades" -ge 3 ]; then
    # Idempotency check
    if $SPLUNK_BIN version 2>/dev/null | grep -q "Splunk $SPLUNK_V10_1_VER"; then
         echo "Already on ${SPLUNK_V10_1_VER}. Skipping Step 3."
    else
        echo ""
        echo "--- Starting Step 3: Upgrading to ${SPLUNK_V10_1_VER} ---"
        if ! wget -q --show-progress "$SPLUNK_V10_1_URL" -O "$SPLUNK_V10_1_RPM"; then
            echo "Splunk ${SPLUNK_V10_1_VER} failed to download"
            exit 1
        fi

        if ! rpm -Uhv "$SPLUNK_V10_1_RPM"; then
            echo "Upgrade to ${SPLUNK_V10_1_VER} failed"
            exit 1
        fi

        echo "Starting Splunk to complete migration to ${SPLUNK_V10_1_VER}..."
        "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes
        rm -f "$SPLUNK_V10_1_RPM"
        echo "--- Step 3 Complete ---"
    fi
fi

echo ""
echo "--- Splunk upgrade process finished. ---"