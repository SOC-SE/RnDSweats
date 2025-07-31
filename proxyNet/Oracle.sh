#!/bin/bash
# ==============================================================================
# setup_wazuh_manager_and_agent_with_yara_v2.sh
#
# v2: Adds a verification step after installation to ensure core files exist
#     before attempting configuration. This prevents errors if the
#     package installation fails.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

# --- Configuration ---
YARA_RULES_DIR="/var/ossec/etc/yara-rules"

# --- Script Validation ---
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ ERROR: This script must be run as root. Please use sudo." >&2
  exit 1
fi

# --- Step 1: Update system and install dependencies ---
echo "INFO: Updating system and installing dependencies..."
dnf install -y curl git gnupg2 yara

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

# --- Step 5: Verify Wazuh Installation ---
echo "INFO: Verifying that Wazuh manager was installed correctly..."
if [ ! -f /var/ossec/etc/ossec.conf ]; then
    echo "❌ ERROR: Wazuh installation failed. The configuration file /var/ossec/etc/ossec.conf was not found." >&2
    echo "Please check the output of the 'dnf install' command above for errors." >&2
    exit 1
fi
echo "INFO: Wazuh installation verified."

# --- Step 6: Configure Manager Decoders and Rules ---
DECODER_FILE="/var/ossec/etc/decoders/local_decoder.xml"
RULES_FILE="/var/ossec/etc/rules/local_rules.xml"

echo "INFO: Ensuring local config files exist..."
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

# --- Step 7: Clone Repositories for Local Agent Protection ---
echo "INFO: Cloning the wazuh-yara integration script for the local agent..."
git clone https://github.com/ADORSYS-GIS/wazuh-yara.git

echo "INFO: Cloning the custom Yara rules repository..."
git clone https://github.com/yara-rules/rules.git "$YARA_RULES_DIR"

# --- Step 8: Set Up Yara Integration on the Local Agent ---
echo "INFO: Copying the yara.sh active response script..."
cp wazuh-yara/scripts/yara.sh /var/ossec/active-response/bin/

echo "INFO: Creating a master index file for all Yara rules..."
find "$YARA_RULES_DIR" -name "*.yar" -printf 'include "%p"\n' > "$YARA_RULES_DIR/index.yar"

echo "INFO: Modifying yara.sh to use the new custom ruleset..."
sed -i "s|YARA_RULES=\"/var/ossec/etc/rules\"|YARA_RULES=\"$YARA_RULES_DIR/index.yar\"|" /var/ossec/active-response/bin/yara.sh

# --- Step 9: Set Permissions ---
echo "INFO: Setting correct file permissions for active response..."
chown root:wazuh /var/ossec/active-response/bin/yara.sh
chmod 750 /var/ossec/active-response/bin/yara.sh
chown -R root:wazuh "$YARA_RULES_DIR"
chmod -R 750 "$YARA_RULES_DIR"

# --- Step 10: Configure the Local Agent for Yara ---
echo "INFO: Configuring the local agent (ossec.conf) for Yara active response..."
# This block checks if the configuration already exists to prevent adding it multiple times.
if ! grep -q "<command>yara</command>" /var/ossec/etc/ossec.conf; then
  sed -i '//a \
  <command>\
    <name>yara</name>\
    <executable>yara.sh</executable>\
    <expect>filename</expect>\
    <timeout_allowed>yes</timeout_allowed>\
  </command>\
\
  <active-response>\
    <command>yara</command>\
    <location>local</location>\
    <rules_id>550,554</rules_id>\
  </active-response>' /var/ossec/etc/ossec.conf
fi

# --- Step 11: Enable and Restart the Wazuh Manager ---
echo "INFO: Enabling and restarting the Wazuh manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl restart wazuh-manager

# --- Step 12: Final Verification ---
echo "INFO: Verifying Wazuh Manager service status..."
sleep 5 # Give the service a moment to start up
if systemctl is-active --quiet wazuh-manager; then
  echo ""
  echo "========================= ✅ SUCCESS ✅ ========================="
  echo "Wazuh Manager is installed and running."
  echo "The local agent is now protected with custom Yara rules."
  echo ""
  echo "You can now proceed with installing and registering your other agents."
  echo "================================================================"
else
  echo "❌ ERROR: Wazuh Manager service failed to start. Please check the logs for errors." >&2
  echo "   # journalctl -u wazuh-manager"
  exit 1
fi

echo "Script finished."
