#!/bin/bash

# ==============================================================================
# CCDC Development - Automated Yara Installer & Rule Downloader (Wazuh/Valhalla)
#
# Description: Installs Yara and downloads the Valhalla ruleset as recommended
#              by Wazuh documentation, placing it in the correct location for
#              Wazuh's Yara integration.
# Author:      Samuel Brucker (Modified)
# Version:     2.0
# ==============================================================================

# --- Configuration ---
# The temporary directory for downloading rules.
TEMP_DIR="/tmp/yara"
# The temporary rule file path.
TEMP_RULES_FILE="$TEMP_DIR/rules/yara_rules.yar"
# The final rule file for production use (Wazuh standard path).
FINAL_RULES_FILE="/var/ossec/etc/yara/rules/production.yar"

# --- Pre-flight Checks ---

# Check 1: Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

# --- Main Execution ---

echo "🚀 Starting automated Yara setup for Wazuh..."

# Step 1: Install Dependencies (Yara & curl)
echo "--------------------------------------------------"
echo "STEP 1: Installing Yara and curl..."
echo "--------------------------------------------------"
if command -v apt-get &> /dev/null; then
    echo "🔎 Debian/Ubuntu based system detected. Using apt-get..."
    apt-get update -y > /dev/null 2>&1
    apt-get install yara curl -y
    
elif command -v dnf &> /dev/null; then
    echo "🔎 RHEL/Fedora based system detected. Using dnf..."
    dnf install yara curl -y
    
elif command -v yum &> /dev/null; then
    echo "🔎 RHEL/CentOS based system detected. Using yum..."
    yum install yara curl -y
    
else
    echo "❌ Unsupported package manager. Please install Yara and curl manually."
    exit 1
fi
echo "✅ Dependencies installed successfully."


# Step 2: Download the Yara Rules from Valhalla
echo "--------------------------------------------------"
echo "STEP 2: Downloading Yara rules from Valhalla..."
echo "--------------------------------------------------"
# Create temporary directory
mkdir -p "$TEMP_DIR/rules"

# Use curl to download the rules with the provided parameters
curl 'https://valhalla.nextron-systems.com/api/v1/get' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    --compressed \
    -H 'Referer: https://valhalla.nextron-systems.com/' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
    --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
    -o "$TEMP_RULES_FILE"

# Check if the download was successful and the file is not empty
if [ ! -s "$TEMP_RULES_FILE" ]; then
    echo "❌ Error: Failed to download the rules file, or the file is empty."
    rm -r "$TEMP_DIR" # Clean up the temporary directory
    exit 1
fi
echo "✅ Rules downloaded successfully to a temporary location."


# Step 3: Move the Rules File to the Production Directory
echo "--------------------------------------------------"
echo "STEP 3: Moving rules to the production directory..."
echo "--------------------------------------------------"
# Create the destination directory if it doesn't exist
mkdir -p "$(dirname "$FINAL_RULES_FILE")"

# Move and rename the downloaded file to the final destination
mv "$TEMP_RULES_FILE" "$FINAL_RULES_FILE"

# Check if the file was moved successfully
if [ -f "$FINAL_RULES_FILE" ]; then
    echo "✅ Successfully moved rules to: $FINAL_RULES_FILE"
else
    echo "❌ Error: Failed to move the rules file."
    rm -r "$TEMP_DIR" # Clean up the temporary directory
    exit 1
fi

# Step 4: Cleanup
echo "--------------------------------------------------"
echo "STEP 4: Cleaning up temporary files..."
echo "--------------------------------------------------"
rm -r "$TEMP_DIR"
echo "✅ Temporary directory removed."

echo "--------------------------------------------------"
echo "🎉 Yara setup and rule installation complete!"
echo ""
echo "You can now use the Wazuh rules file for scanning:"
echo "yara $FINAL_RULES_FILE /path/to/scan/"
echo "--------------------------------------------------"
