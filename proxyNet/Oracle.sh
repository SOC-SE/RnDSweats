#!/bin/bash
# ==============================================================================
# setup_wazuh_manager_with_yara_v3.sh
#
# v3: Fixes an issue where parent directories for config files might not
#     exist immediately after installation.
#
# Configures a server (designed for Oracle Linux 9) to install the Wazuh Manager
# and configures it for Yara integration.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

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

# --- Step 5: Add YARA decoders and rules ---
DECODER_DIR="/var/ossec/etc/decoders"
RULES_DIR="/var/ossec/etc/rules"
DECODER_FILE="$DECODER_DIR/local_decoder.xml"
RULES_FILE="$RULES_DIR/local_rules.xml"

echo "INFO: Ensuring local config directories and files exist..."
# Create the parent directories if they don't exist.
mkdir -p "$DECODER_DIR"
mkdir -p "$RULES_DIR"

# Create the files if they don't exist.
touch "$DECODER_FILE"
touch "$RULES_FILE"

echo "INFO: Adding YARA decoders to $DECODER_FILE..."
cat >> "$DECODER_FILE" << EOF

<decoder name="yara_decoder">
  <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
  <parent>yara_decoder</parent>
  <regex>wazuh-yara: (\S+) - Scan result: (\S+) (\S+)</regex>
  <order>log_type, yara_rule, yara_scanned_file</order>
</decoder>
EOF

echo "INFO: Adding YARA rules to $RULES_FILE..."
cat >> "$RULES_FILE" << EOF

<group name="yara,">
  <rule id="100020" level="7">
    <if_sid>550, 554</if_sid>
    <field name="yara_rule" type="text">\.yar</field>
    <description>File '$(file)' is infected. Yara rule: $(yara_rule)</description>
  </rule>

  <rule id="100021" level="12">
    <if_sid>100020</if_sid>
    <match>Trojan|Backdoor|Exploit|Virus|Malware|Ransomware|Rootkit|Spyware|Adware|Phishing|Keylogger</match>
    <description>High-risk malware detected in file '$(file)'. Yara rule: $(yara_rule)</description>
  </rule>
</group>
EOF

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
  echo "Wazuh Manager is installed, configured for Yara, and running."
  echo ""
  echo "You can now proceed with installing and registering your agents."
  echo "================================================================"
else
  echo "❌ ERROR: Wazuh Manager service failed to start. Please check the logs for errors." >&2
  echo "   # journalctl -u wazuh-manager"
  exit 1
fi

echo "Script finished."
