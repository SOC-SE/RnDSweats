#!/bin/bash

# ==============================================================================
# CCDC Development - Automated Yara Installer & Rule Sanitizer
#
# Description: Installs Yara, clones the Neo23x0/signature-base ruleset,
#              removes files that cause errors in standard Yara, and compiles
#              the remaining rules into a single production file.
# Author:      Samuel Brucker
# Version:     1.0
# ==============================================================================

# --- Configuration ---
# The Git repository containing the Yara rules.
RULES_REPO="https://github.com/Neo23x0/signature-base.git"
# The local directory to clone the rules into.
RULES_DIR="/opt/yara_rules/signature-base"
# The final, compiled rule file for production use.
COMPILED_RULES_FILE="/opt/yara_rules/production.yar"

# --- Pre-flight Checks ---

# Check 1: Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

# --- Main Execution ---

echo "🚀 Starting automated Yara setup..."

# Step 1: Install Dependencies (Yara)
echo "--------------------------------------------------"
echo "STEP 1: Installing Yara..."
echo "--------------------------------------------------"
if command -v apt-get &> /dev/null; then
    echo "🔎 Debian/Ubuntu based system detected. Using apt-get..."
    apt-get update -y > /dev/null 2>&1
    apt-get install yara -y

elif command -v dnf &> /dev/null; then
    echo "🔎 RHEL/Fedora based system detected. Using dnf..."
    dnf install yara -y

elif command -v yum &> /dev/null; then
    echo "🔎 RHEL/CentOS based system detected. Using yum..."
    yum install yara -y

else
    echo "❌ Unsupported package manager. Please install Yara manually."
    exit 1
fi
echo "✅ Yara installed successfully."


# Step 2: Clone the Yara Rules Repository
echo "--------------------------------------------------"
echo "STEP 2: Cloning the Yara rules repository..."
echo "--------------------------------------------------"
if [ -d "$RULES_DIR" ]; then
    echo "🔎 Rules directory already exists. Pulling latest changes..."
    (cd "$RULES_DIR" && git pull)
else
    echo "🔎 Cloning repository to $RULES_DIR..."
    git clone "$RULES_REPO" "$RULES_DIR"
fi
echo "✅ Rules repository synced successfully."


# Step 3: Sanitize the Ruleset
echo "--------------------------------------------------"
echo "STEP 3: Sanitizing ruleset by removing incompatible files..."
echo "--------------------------------------------------"

# Array of files that cause errors due to undefined external variables.
# These paths are relative to the 'yara' subdirectory in the cloned repo.
FILES_TO_REMOVE=(
    "generic_anomalies.yar"
    "general_cloaking.yar"
    "gen_webshells_ext_vars.yar"
    "thor_inverse_matches.yar"
    "yara_mixed_ext_vars.yar"
    "configured_vulns_ext_vars.yar"
    "gen_fake_amsi_dll.yar"
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar"
    "yara-rules_vuln_drivers_strict_renamed.yar"
)

for file in "${FILES_TO_REMOVE[@]}"; do
    # The rules are in a 'yara' subdirectory within the main repo directory
    TARGET_FILE="$RULES_DIR/yara/$file"
    if [ -f "$TARGET_FILE" ]; then
        echo "   - Removing: $file"
        rm "$TARGET_FILE"
    else
        echo "   - Warning: Could not find $file to remove. It may have been renamed or deleted upstream."
    fi
done
echo "✅ Ruleset sanitized."


# Step 4: Compile All Valid Rules into a Single File
echo "--------------------------------------------------"
echo "STEP 4: Compiling all valid .yar rules into a single production file..."
echo "--------------------------------------------------"

# Create an index file that lists all .yar files to be included
INDEX_FILE="/tmp/yara_rule_index.txt"
# We specifically look in the yara subdirectory of the cloned repo
find "$RULES_DIR/yara" -type f -name "*.yar" > "$INDEX_FILE"

# The yara command can take an index file of rules to compile
yara -w -f "$INDEX_FILE" "$COMPILED_RULES_FILE"

# Check if the compilation was successful
if [ $? -eq 0 ]; then
    echo "✅ Successfully compiled rules into: $COMPILED_RULES_FILE"
else
    echo "❌ Error: Yara compilation failed. Please check for rule syntax errors."
    rm "$INDEX_FILE"
    exit 1
fi

rm "$INDEX_FILE"

echo "--------------------------------------------------"
echo "🎉 Yara setup and rule compilation complete!"
echo ""
echo "You can now use the compiled rules file for scanning:"
echo "yara $COMPILED_RULES_FILE /path/to/scan/"
echo "--------------------------------------------------"
