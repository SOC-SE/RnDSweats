#!/bin/bash

# This script automates the installation of specific rules, decoders, and scripts
# from the SOCFortress wazuh-rules repository for a Wazuh manager.
# It must be run with root privileges.

# --- Configuration ---
REPO_URL="https://github.com/socfortress/wazuh-rules/archive/refs/heads/Wazuh-Rules-main.zip"
TEMP_DIR="/tmp/wazuh_rules_temp"
EXTRACTED_FOLDER_NAME="wazuh-rules-Wazuh-Rules-main" # The folder name inside the zip

# Wazuh Directories
WAZUH_RULES_DIR="/var/ossec/etc/rules"
WAZUH_DECODERS_DIR="/var/ossec/etc/decoders"
WAZUH_INTEGRATIONS_DIR="/var/ossec/integrations"
WAZUH_AR_DIR="/var/ossec/active-response/bin"

# --- Pre-run Checks ---
# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# Check for necessary tools
for cmd in wget unzip; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: Required command '$cmd' is not installed."
    echo "Please install it using your package manager (e.g., 'apt install $cmd' or 'yum install $cmd')."
    exit 1
  fi
done

# --- Main Script Logic ---
echo "--- Starting SOCFortress Custom Wazuh Rules Installation ---"

# 1. Cleanup and Setup Temporary Directory
echo "[1/5] Setting up temporary directory..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR" || exit 1

# 2. Download and Extract Repository
echo "[2/5] Downloading and extracting repository from GitHub..."
wget -q --show-progress "$REPO_URL" -O wazuh-rules.zip
unzip -q wazuh-rules.zip
if [ ! -d "$EXTRACTED_FOLDER_NAME" ]; then
    echo "Error: Could not find the extracted folder '$EXTRACTED_FOLDER_NAME'. Exiting."
    exit 1
fi
cd "$EXTRACTED_FOLDER_NAME" || exit 1

# 3. Copy Files to Wazuh Directories
echo "[3/5] Copying selected rules, decoders, and scripts..."

# List of files to copy: {source} -> {destination_directory}
declare -A files_to_copy=(
    # Auditd
    ["Auditd/200110-auditd.xml"]="rules"
    ["Auditd/auditd_decoders.xml"]="decoders"
    # Exclusion Rules
    ["Exclusion Rules/900000-exclusion_rules.xml"]="rules"
    # Domain Stats
    ["Domain Stats/100610-domain_stats_rules.xml"]="rules"
    ["Domain Stats/100080-alienvault.xml"]="rules"
    ["Domain Stats/custom-dnsstats.py"]="integrations"
    ["Domain Stats/custom-dnsstats"]="integrations"
    # Healthcheck
    ["Healthcheck/200990-healthcheck.xml"]="rules"
    # Manager
    ["Manager/500010-manager_logs.xml"]="rules"
    ["Manager/decoder-manager-logs.xml"]="decoders"
    # Modsecurity
    ["Modsecurity/100099-Modsecurity.xml"]="rules"
    # Nmap
    ["Nmap/200400-nmap-scan_rules.xml"]="rules"
    ["Nmap/nmap_scan.py"]="integrations"
    # SCA
    ["SCA/200910-wazuh_sca.xml"]="rules"
    # Software
    ["Software/201015-software.xml"]="rules"
    # Suricata
    ["Suricata/100002-suricata.xml"]="rules"
    # Wazuh Inventory
    ["Wazuh Inventory/200900-wazuh_inventory.xml"]="rules"
    # Yara
    ["Yara/200100-yara_rules.xml"]="rules"
    ["Yara/yara_decoders.xml"]="decoders"
    ["Yara/yara_full_scan.sh"]="ar"
)

for src_path in "${!files_to_copy[@]}"; do
    dest_type=${files_to_copy[$src_path]}
    dest_dir=""

    case $dest_type in
        "rules") dest_dir="$WAZUH_RULES_DIR" ;;
        "decoders") dest_dir="$WAZUH_DECODERS_DIR" ;;
        "integrations") dest_dir="$WAZUH_INTEGRATIONS_DIR" ;;
        "ar") dest_dir="$WAZUH_AR_DIR" ;;
    esac

    if [ -f "$src_path" ]; then
        echo "  - Copying $(basename "$src_path") to $dest_dir/"
        cp "$src_path" "$dest_dir/"
    else
        echo "  - Warning: Source file not found: $src_path"
    fi
done

# 4. Set Permissions and Ownership
echo "[4/5] Setting correct permissions and ownership for new files..."
chown -R wazuh:wazuh "$WAZUH_RULES_DIR" "$WAZUH_DECODERS_DIR" "$WAZUH_INTEGRATIONS_DIR" "$WAZUH_AR_DIR"
chmod 660 "$WAZUH_RULES_DIR"/* "$WAZUH_DECODERS_DIR"/*
chmod 770 "$WAZUH_INTEGRATIONS_DIR"/* "$WAZUH_AR_DIR"/*

# 5. Cleanup
echo "[5/5] Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo "--- Installation Complete ---"