#!/bin/bash
# ==============================================================================
# setup_wazuh_manager_with_yara.sh
#
# Configures a server (designed for Oracle Linux 9, but adaptable) to install
# the Wazuh Manager and the required components for the ADORSYS-GIS YARA
# integration. This script ensures the manager can correctly interpret
# alerts from agents running the yara.sh active response.
#
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

# --- Configuration ---
# Repository for the Wazuh-YARA integration scripts, rules, and decoders.
ADORSYS_YARA_REPO_URL="https://github.com/ADORSYS-GIS/wazuh-yara.git"


# --- Script Validation ---
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ ERROR: This script must be run as root. Please use sudo." >&2
  exit 1
fi


# --- Step 1: Update system and install dependencies ---
echo "INFO: Updating system and installing dependencies..."
dnf install -y curl git gnupg2


# --- Step 2: Add Wazuh repository ---
echo "INFO: Adding Wazuh repository..."
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
protect=1
EOF


# --- Step 3: Import Wazuh GPG key ---
echo "INFO: Importing Wazuh GPG key..."
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH


# --- Step 4: Install wazuh-manager ---
echo "INFO: Installing wazuh-manager package..."
dnf install -y wazuh-manager


# --- Step 5: Install YARA Manager Components ---
echo "INFO: Deploying YARA decoders and rules for the manager..."
TMP_DIR=$(mktemp -d)
echo "INFO: Cloning repository from $ADORSYS_YARA_REPO_URL..."
git clone --depth 1 "$ADORSYS_YARA_REPO_URL" "$TMP_DIR"

# Define source and destination paths for manager components
YARA_DECODER_SRC="$TMP_DIR/manager/decoders/yara_decoders.xml"
YARA_RULE_SRC="$TMP_DIR/manager/rules/yara_rules.xml"
DECODER_DEST_DIR="/var/ossec/etc/decoders"
RULE_DEST_DIR="/var/ossec/etc/rules"

# Copy decoder and rule files
echo "INFO: Copying YARA decoder and rule files to Wazuh manager directories..."
cp "$YARA_DECODER_SRC" "$DECODER_DEST_DIR/"
cp "$YARA_RULE_SRC" "$RULE_DEST_DIR/"

# Set correct ownership to ensure the manager can read the files
echo "INFO: Setting correct ownership for new files..."
chown root:wazuh "$DECODER_DEST_DIR/yara_decoders.xml"
chown root:wazuh "$RULE_DEST_DIR/yara_rules.xml"

echo "INFO: Cleaning up temporary directory..."
rm -rf "$TMP_DIR"


# --- Step 6: Enable and start the Wazuh Manager service ---
echo "INFO: Enabling and starting the Wazuh manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl restart wazuh-manager


# --- Step 7: Verification and Final Instructions ---
echo "INFO: Verifying Wazuh Manager service status..."
if systemctl is-active --quiet wazuh-manager; then
  echo ""
  echo "========================= ✅ SUCCESS ✅ ========================="
  echo "Wazuh Manager is installed and running."
  echo "The necessary YARA decoders and rules have been deployed."
  echo "The manager is now ready to receive and process YARA alerts from your agents."
  echo ""
  echo "You can now proceed with registering your agents."
  echo "================================================================"
else
  echo "❌ ERROR: Wazuh Manager service failed to start. Please check the logs for errors." >&2
  echo "   # journalctl -u wazuh-manager"
  exit 1
fi

echo "Script finished."
