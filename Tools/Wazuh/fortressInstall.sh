#!/bin/bash

# This script automates the installation of specific rules, decoders, and scripts
# from the SOCFortress wazuh-rules repository by cloning the repo, copying
# necessary files, and then cleaning up.
# It must be run with root privileges.

# --- Configuration ---
REPO_URL="https://github.com/socfortress/wazuh-rules.git"
TEMP_DIR="/tmp/socfortress-wazuh-rules"

# Wazuh Directories
WAZUH_RULES_DIR="/var/ossec/etc/rules"
WAZUH_DECODERS_DIR="/var/ossec/etc/decoders"
WAZUH_INTEGRATIONS_DIR="/var/ossec/integrations"
WAZUH_AR_DIR="/var/ossec/active-response/bin"

# --- Pre-run Checks ---
# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Exiting."
   exit 1
fi

# Check for git
if ! command -v git &> /dev/null; then
    echo "Error: 'git' command not found. Please install it to continue."
    echo "e.g., 'sudo apt install git' or 'sudo yum install git'"
    exit 1
fi

# --- Main Script Logic ---
echo "--- Starting SOCFortress Custom Wazuh Rules Installation (v2) ---"

# 1. Cleanup and Setup Temporary Directory
echo "[1/5] Cleaning up old temporary directories..."
rm -rf "$TEMP_DIR"

# 2. Clone Repository
echo "[2/5] Cloning the entire repository to a temporary location..."
if ! git clone --depth 1 "$REPO_URL" "$TEMP_DIR"; then
    echo "Error: Failed to clone the repository. Please check your connection and the URL."
    exit 1
fi

# 3. Copy Files to Wazuh Directories
echo "[3/5] Copying selected rules, decoders, and scripts..."

# List of files to copy from the cloned repo
declare -A files_to_copy=(
    # Source Path relative to repo root -> Destination Type
    ["Auditd/200110-auditd.xml"]="rules"
    ["Auditd/auditd_decoders.xml"]="decoders"
    ["Exclusion Rules/900000-exclusion_rules.xml"]="rules"
    ["Domain Stats/100610-domain_stats_rules.xml"]="rules"
    ["Domain Stats/100080-alienvault.xml"]="rules"
    ["Domain Stats/custom-dnsstats.py"]="integrations"
    ["Domain Stats/custom-dnsstats"]="integrations"
    ["Healthcheck/200990-healthcheck.xml"]="rules"
    ["Manager/500010-manager_logs.xml"]="rules"
    ["Manager/decoder-manager-logs.xml"]="decoders"
    ["Modsecurity/100099-Modsecurity.xml"]="rules"
    ["Nmap/200400-nmap-scan_rules.xml"]="rules"
    ["Nmap/nmap_scan.py"]="integrations"
    ["SCA/200910-wazuh_sca.xml"]="rules"
    ["Software/201015-software.xml"]="rules"
    ["Suricata/100002-suricata.xml"]="rules"
    ["Wazuh Inventory/200900-wazuh_inventory.xml"]="rules"
    ["Yara/200100-yara_rules.xml"]="rules"
    ["Yara/yara_decoders.xml"]="decoders"
    ["Yara/yara_full_scan.sh"]="ar"
)

for src_path in "${!files_to_copy[@]}"; do
    dest_type=${files_to_copy[$src_path]}
    full_src_path="$TEMP_DIR/$src_path"
    dest_dir=""

    case $dest_type in
        "rules") dest_dir="$WAZUH_RULES_DIR" ;;
        "decoders") dest_dir="$WAZUH_DECODERS_DIR" ;;
        "integrations") dest_dir="$WAZUH_INTEGRATIONS_DIR" ;;
        "ar") dest_dir="$WAZUH_AR_DIR" ;;
    esac

    if [ -f "$full_src_path" ]; then
        echo "  - Copying $(basename "$full_src_path") to $dest_dir/"
        cp "$full_src_path" "$dest_dir/"
    else
        echo "  - Warning: Source file not found in repository: $full_src_path"
    fi
done

# 4. Set Permissions and Ownership
echo "[4/5] Setting correct permissions and ownership for new files..."
# Set ownership for all new files
chown wazuh:wazuh "$WAZUH_RULES_DIR"/* "$WAZUH_DECODERS_DIR"/* "$WAZUH_INTEGRATIONS_DIR"/* "$WAZUH_AR_DIR"/* 2>/dev/null

# Set permissions: Read/Write for owner/group on rules/decoders
chmod 660 "$WAZUH_RULES_DIR"/* "$WAZUH_DECODERS_DIR"/* 2>/dev/null
# Set permissions: Read/Write/Execute for owner/group on scripts
chmod 770 "$WAZUH_INTEGRATIONS_DIR"/* "$WAZUH_AR_DIR"/* 2>/dev/null

# 5. Cleanup
echo "[5/5] Cleaning up temporary repository clone..."
rm -rf "$TEMP_DIR"

echo
echo "--- Installation Complete ---"
echo "The script has finished. Now, you must manually configure ossec.conf."
echo
echo "Next steps:"
echo "1. Manually edit '/var/ossec/etc/ossec.conf' using the provided guide."
echo "2. Validate your configuration: /var/ossec/bin/wazuh-control check"
echo "3. Restart the Wazuh manager: systemctl restart wazuh-manager"

