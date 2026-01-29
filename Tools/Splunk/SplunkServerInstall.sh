#!/bin/bash
set -euo pipefail
# ==============================================================================
# Script Name: SplunkServerInstall.sh
# Description: Distro-agnostic Splunk Enterprise install script.
#              Backs up licenses, nukes old install, installs fresh,
#              restores licenses, sets up admin user and props.conf.
# Author: Samuel Brucker 2024-2026
# Version: 2.0
#
# Supported Systems:
#   - Ubuntu/Debian (apt, .deb)
#   - Fedora/RHEL/Oracle/Rocky/Alma (dnf/yum, .rpm)
#
# Usage:
#   sudo ./SplunkServerInstall.sh
#
# ==============================================================================

# --- Configuration ---
SPLUNK_VERSION="10.0.2"
SPLUNK_BUILD="e2d18b4767e9"
SPLUNK_HOME="/opt/splunk"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root"
    exit 1
fi

# --- Detect distro and set package info ---
if command -v dnf &>/dev/null; then
    DISTRO="rhel"
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    DISTRO="rhel"
    PKG_MGR="yum"
elif command -v apt-get &>/dev/null; then
    DISTRO="debian"
    PKG_MGR="apt-get"
else
    echo "[ERROR] No supported package manager found (dnf, yum, apt-get)"
    exit 1
fi

if [[ "$DISTRO" == "rhel" ]]; then
    SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
else
    SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.deb"
fi
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PKG}"

# --- Prompt for Splunk admin password ---
if [[ -z "${SPLUNK_PASS:-}" ]]; then
    while true; do
        echo -n "Enter password for Splunk admin user: "
        stty -echo
        read -r pass1
        stty echo
        echo
        echo -n "Confirm password: "
        stty -echo
        read -r pass2
        stty echo
        echo
        if [[ "$pass1" == "$pass2" ]] && [[ -n "$pass1" ]]; then
            SPLUNK_PASS="$pass1"
            break
        else
            echo "Passwords do not match or are empty. Please try again."
        fi
    done
fi

# --- Handle existing installation ---
BACKUP_DIR="/home/splbackup"
if [[ -d "$SPLUNK_HOME" ]]; then
    echo "Splunk is already installed at $SPLUNK_HOME."
    read -r -p "Completely DELETE and reinstall Splunk? (y/N): " choice
    case "$choice" in
        [yY]|[yY][eE][sS])
            echo "Stopping and removing old Splunk..."
            $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
            $SPLUNK_HOME/bin/splunk disable boot-start 2>/dev/null || true
            pkill -f splunkd 2>/dev/null || true

            # Backup licenses
            mkdir -p "$BACKUP_DIR"
            if [[ -d "$SPLUNK_HOME/etc/licenses" ]]; then
                cp -R "$SPLUNK_HOME/etc/licenses/." "$BACKUP_DIR/" 2>/dev/null || true
                echo "Licenses backed up to $BACKUP_DIR"
            fi

            # Remove package and directory
            if [[ "$DISTRO" == "rhel" ]]; then
                $PKG_MGR remove -y splunk 2>/dev/null || rpm -e splunk 2>/dev/null || true
            else
                apt-get purge -y splunk 2>/dev/null || dpkg -r splunk 2>/dev/null || true
            fi
            rm -rf "$SPLUNK_HOME"
            echo "Old Splunk removed."
            ;;
        *)
            echo "Aborting. Splunk was not changed."
            exit 0
            ;;
    esac
fi

# --- Install prerequisites (RHEL) ---
if [[ "$DISTRO" == "rhel" ]]; then
    echo "Installing prerequisites..."
    $PKG_MGR install -y libxcrypt-compat 2>/dev/null || true
fi

# --- Download Splunk ---
echo "Downloading Splunk $SPLUNK_VERSION..."
if ! wget -q -O "$SPLUNK_PKG" "$SPLUNK_URL"; then
    echo "[ERROR] Failed to download Splunk. Exiting."
    exit 1
fi

# --- Install Splunk ---
echo "Installing Splunk $SPLUNK_VERSION..."
if [[ "$DISTRO" == "rhel" ]]; then
    $PKG_MGR install -y "./$SPLUNK_PKG" 2>/dev/null || rpm -i "$SPLUNK_PKG"
else
    DEBIAN_FRONTEND=noninteractive apt-get install -y "./$SPLUNK_PKG" 2>/dev/null || dpkg -i "$SPLUNK_PKG"
fi
rm -f "$SPLUNK_PKG"

# --- Create admin user via seed ---
echo "Creating admin user..."
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $SPLUNK_PASS
EOF
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/user-seed.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# --- Install custom props.conf if available ---
PROPS_CONF=""
for props_path in "$SCRIPT_DIR/props.conf" "/tmp/props.conf"; do
    if [[ -f "$props_path" ]]; then
        PROPS_CONF="$props_path"
        break
    fi
done

if [[ -n "$PROPS_CONF" ]]; then
    echo "Installing custom props.conf from $PROPS_CONF..."
    cp "$PROPS_CONF" "$SPLUNK_HOME/etc/system/local/props.conf"
    chown splunk:splunk "$SPLUNK_HOME/etc/system/local/props.conf"
else
    echo "[WARN] props.conf not found, skipping."
fi

# --- Restore backed up licenses ---
if [[ -d "$BACKUP_DIR" ]] && [[ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
    echo "Restoring licenses..."
    mkdir -p "$SPLUNK_HOME/etc/licenses"
    cp -r "$BACKUP_DIR/." "$SPLUNK_HOME/etc/licenses/"
    chown -R splunk:splunk "$SPLUNK_HOME/etc/licenses"
fi

# --- Start Splunk ---
echo "Starting Splunk and accepting license..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt

echo "Enabling boot start..."
$SPLUNK_HOME/bin/splunk enable boot-start --accept-license --answer-yes --no-prompt

echo ""
echo "========================================================"
echo "  Splunk $SPLUNK_VERSION installation complete!"
echo "  Web UI: https://localhost:8000"
echo "========================================================"
