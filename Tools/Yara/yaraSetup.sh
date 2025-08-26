#!/bin/bash

# ==============================================================================
# CCDC Development - Automated Yara Installer & Rule Sanitizer
#
# Description: Installs Yara, clones the Neo23x0/signature-base ruleset,
#              removes files that cause errors in standard Yara, and compiles
#              the remaining rules into a single production file.
# Author:      Samuel Brucker
# Version:     1.1 (Corrected)
# ==============================================================================
# --- Pre-flight Checks ---

# Check 1: Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

# --- Main Execution ---

echo "🚀 Starting automated Yara setup..."

# Step 1: Install Dependencies (Yara & jq)
echo "--------------------------------------------------"
echo "STEP 1: Installing Yara and jq..."
echo "--------------------------------------------------"
if command -v apt-get &> /dev/null; then
    echo "🔎 Debian/Ubuntu based system detected. Using apt-get..."
    apt-get update -y > /dev/null 2>&1
    apt-get install yara jq -y
    
elif command -v dnf &> /dev/null; then
    echo "🔎 RHEL/Fedora based system detected. Using dnf..."
    dnf install yara jq -y
    
elif command -v yum &> /dev/null; then
    echo "🔎 RHEL/CentOS based system detected. Using yum..."
    yum install yara jq -y
    
else
    echo "❌ Unsupported package manager. Please install Yara and jq manually."
    exit 1
fi
echo "✅ Yara and jq installed successfully."


# Step 2: Clone the Yara Rules Repository
echo "--------------------------------------------------"
echo "STEP 2: Cloning the Yara rules repository..."
echo "--------------------------------------------------"

SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Folder where Yara rules (files) will be placed -------------------------#
git_repo_folder="/usr/local/signature-base"
yara_file_extenstions=( ".yar" )
yara_rules_list="/usr/local/signature-base/yara_rules_list.yar"

#------------------------- Main workflow --------------------------#

# Update Github Repo
cd $git_repo_folder
git clone https://github.com/Neo23x0/signature-base.git

# Remove .yar files not compatible with standard Yara package
rm $git_repo_folder/yara/generic_anomalies.yar $git_repo_folder/yara/general_cloaking.yar $git_repo_folder/yara/thor_inverse_matches.yar $git_repo_folder/yara/yara_mixed_ext_vars.yar $git_repo_folder/yara/apt_cobaltstrike.yar $git_repo_folder/yara/apt_tetris.yar $git_repo_folder/yara/gen_susp_js_obfuscatorio.yar $git_repo_folder/yara/configured_vulns_ext_vars.yar $git_repo_folder/yara/gen_webshells_ext_vars.yar $git_repo_folder/yara/expl_connectwise_screenconnect_vuln_feb24.yar

# Create File with rules to be compiled
if [ ! -f $yara_rules_list ]
then
    /usr/bin/touch $yara_rules_list
else rm $yara_rules_list
fi
for e in "${yara_file_extenstions[@]}"
do
  for f1 in $( find $git_repo_folder/yara -type f | grep -F $e ); do
    echo "include \"""$f1"\""" >> $yara_rules_list
  done
done
# Compile Yara Rules
/usr/share/yara/yara-4.2.3/yarac $yara_rules_list /usr/local/signature-base/yara_base_ruleset_compiled.yar
IFS=$SAVEIFS




echo "--------------------------------------------------"
echo "🎉 Yara setup and rule combination complete!"
echo ""
echo "You can now use the combined rules file for scanning:"
echo "yara /usr/local/signature-base/yara_base_ruleset_compiled.yar /path/to/scan/"
echo "--------------------------------------------------"
