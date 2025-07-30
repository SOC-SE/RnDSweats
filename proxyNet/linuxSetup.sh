#!/bin/bash
# ==============================================================================
# setup_linux_client_with_bartblaze.sh
#
# Configures Linux servers (CentOS/RHEL/Fedora, Debian/Ubuntu) to install
# and configure the Wazuh Agent.
#
# This version implements YARA integration using the ADORSYS-GIS Active
# Response method and enhances it by adding the comprehensive YARA ruleset
# from the bartblaze community repository.
#
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

# --- Configuration ---
# IP address of your Wazuh Manager.
WAZUH_MANAGER_IP="172.20.241.20"
# Repository for the Wazuh-YARA integration scripts and base rules.
ADORSYS_YARA_REPO_URL="https://github.com/ADORSYS-GIS/wazuh-yara.git"
# Repository for the comprehensive bartblaze community YARA rules.
BARTBLAZE_YARA_REPO_URL="https://github.com/bartblaze/Yara-rules.git"
# Path to the Wazuh agent configuration file.
OSSEC_CONF="/var/ossec/etc/ossec.conf"


# --- Script Validation ---
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ ERROR: This script must be run as root. Please use sudo." >&2
  exit 1
fi

# --- Step 1: Detect distribution ---
echo "INFO: Detecting Linux distribution..."
if [ -f /etc/redhat-release ]; then
  DISTRO="rpm"
elif [ -f /etc/debian_version ]; then
  DISTRO="deb"
else
  echo "❌ ERROR: Unsupported distribution. This script supports RPM (CentOS, RHEL, Fedora) and DEB (Debian, Ubuntu) based systems." >&2
  exit 1
fi
echo "INFO: Detected a $DISTRO-based system."


# --- Step 2: Install Wazuh Agent and Dependencies ---
echo "INFO: Installing Wazuh Agent and dependencies..."
if [ "$DISTRO" == "rpm" ]; then
  yum install -y curl git epel-release
  yum install -y yara
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
  WAZUH_MANAGER="$WAZUH_MANAGER_IP" yum install -y wazuh-agent
elif [ "$DISTRO" == "deb" ]; then
  apt-get update -y
  apt-get install -y curl git yara gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /etc/apt/keyrings/wazuh.gpg
  echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
  apt-get update -y
  WAZUH_MANAGER="$WAZUH_MANAGER_IP" apt-get install -y wazuh-agent
fi


# --- Step 3: Enable and Start the Agent ---
echo "INFO: Enabling and starting the Wazuh Agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent


# --- Step 4: Deploy YARA Integration Components ---
echo "INFO: Deploying YARA integration from ADORSYS-GIS..."
TMP_DIR_ADORSYS=$(mktemp -d)
echo "INFO: Cloning repository from $ADORSYS_YARA_REPO_URL..."
git clone --depth 1 "$ADORSYS_YARA_REPO_URL" "$TMP_DIR_ADORSYS"

# Define destination paths
AR_BIN_DIR="/var/ossec/active-response/bin"
YARA_RULES_DIR="/var/ossec/etc/yara"

# Create directories and copy the active response script and base rules
echo "INFO: Creating directories and copying YARA files..."
mkdir -p "$AR_BIN_DIR" "$YARA_RULES_DIR"
cp "$TMP_DIR_ADORSYS/agent/linux/yara.sh" "$AR_BIN_DIR/"
cp "$TMP_DIR_ADORSYS/yara_rules/yara_rules.yar" "$YARA_RULES_DIR/"

# --- FIX: Modify the yara.sh script to scan the entire rules directory ---
# The original script hardcodes a single file, ignoring all other rules.
# This change ensures all .yar/.yara files in the directory are used.
echo "INFO: Patching yara.sh to use the entire rules directory..."
sed -i 's|YARA_RULES_PATH="/var/ossec/etc/yara/yara_rules.yar"|YARA_RULES_PATH="/var/ossec/etc/yara/"|' "$AR_BIN_DIR/yara.sh"

echo "INFO: Cleaning up ADORSYS-GIS temporary directory..."
rm -rf "$TMP_DIR_ADORSYS"


# --- Step 5: Deploy bartblaze Community YARA Rules ---
echo "INFO: Deploying additional community YARA rules from bartblaze..."
TMP_DIR_BARTBLAZE=$(mktemp -d)
echo "INFO: Cloning repository from $BARTBLAZE_YARA_REPO_URL..."
git clone --depth 1 "$BARTBLAZE_YARA_REPO_URL" "$TMP_DIR_BARTBLAZE"

# Copy all .yar and .yara files into the same rules directory
echo "INFO: Copying bartblaze rules..."
find "$TMP_DIR_BARTBLAZE" -type f \( -name "*.yar" -o -name "*.yara" \) -exec cp {} "$YARA_RULES_DIR/" \;

echo "INFO: Cleaning up bartblaze temporary directory..."
rm -rf "$TMP_DIR_BARTBLAZE"


# --- Step 6: Set Permissions and Configure Wazuh Agent ---
echo "INFO: Setting correct permissions for all YARA integration files..."
# Set permissions for the active response script
chown -R root:wazuh "$AR_BIN_DIR"
chmod 750 "$AR_BIN_DIR/yara.sh"

# Set permissions for the entire YARA rules directory
chown -R wazuh:wazuh "$YARA_RULES_DIR"
find "$YARA_RULES_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) -exec chmod 640 {} \;

echo "INFO: Configuring Wazuh agent for YARA Active Response..."
CONFIG_BACKUP_FILE="$OSSEC_CONF.bak-$(date +%F)"
cp "$OSSEC_CONF" "$CONFIG_BACKUP_FILE"

# Define the XML blocks to insert into ossec.conf
ACTIVE_RESPONSE_CONFIG=$(cat <<'EOF'

  <active-response>
    <command>yara</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
    <timeout>120</timeout>
  </active-response>
EOF
)

LOCALFILE_CONFIG=$(cat <<'EOF'

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
EOF
)

# Insert the new configuration blocks before the </ossec_config> closing tag
# This avoids issues if the blocks already exist.
if ! grep -q "<command>yara</command>" "$OSSEC_CONF"; then
    awk -v ar_config="$ACTIVE_RESPONSE_CONFIG" -v lf_config="$LOCALFILE_CONFIG" '
      /<\/ossec_config>/ {
        print ar_config;
        print lf_config;
      }
      { print }
    ' "$CONFIG_BACKUP_FILE" > "$OSSEC_CONF"
    echo "INFO: YARA Active Response configuration added to $OSSEC_CONF."
else
    echo "INFO: YARA Active Response configuration already exists in $OSSEC_CONF. Skipping."
fi


# --- Step 7: Restart Wazuh Agent to Apply Changes ---
echo "INFO: Restarting the Wazuh Agent to apply new configuration..."
systemctl restart wazuh-agent
systemctl status wazuh-agent --no-pager

# --- Final Instructions ---
echo ""
echo "========================= ⚠️ IMPORTANT - MANUAL ACTION REQUIRED ⚠️ ========================="
echo "✅ AGENT SCRIPT FINISHED. Now, you must complete the setup on your WAZUH MANAGER."
echo ""
echo "1. On your Wazuh Manager server, clone the ADORSYS-GIS repository:"
echo "   # git clone $ADORSYS_YARA_REPO_URL"
echo ""
echo "2. Copy the rules and decoders to your Wazuh manager's ruleset directory:"
echo "   # cp wazuh-yara/manager/decoders/yara_decoders.xml /var/ossec/etc/decoders/"
echo "   # cp wazuh-yara/manager/rules/yara_rules.xml /var/ossec/etc/rules/"
echo ""
echo "3. Restart the Wazuh Manager to load the new rules:"
echo "   # systemctl restart wazuh-manager"
echo ""
echo "The integration will not generate alerts until these manager-side steps are completed."
echo "=========================================================================================="
echo "Script finished."
