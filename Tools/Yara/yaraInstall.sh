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

# Install Dependencies (Yara & jq)
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