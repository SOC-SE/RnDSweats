#!/bin/bash

# ==============================================================================
# CCDC Development - Quick & Dirty Auditd Installer
#
# Description: Installs auditd, enables the service, copies a local 
#              audit.rules file, and restarts the service.
# Author:      CCDC Development
# Version:     1.1
# ==============================================================================

# --- Configuration ---
# The name of your custom rules file, expected in the same directory as this script.
RULES_FILE="audit.rules"
# The destination for the rules file. Naming it 99- makes it load last.
DEST_RULES_FILE="/etc/audit/rules.d/audit.rules"

# --- Pre-flight Checks ---

# Check 1: Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

# Check 2: Ensure the audit.rules file exists before we start.
if [ ! -f "$RULES_FILE" ]; then
  echo "❌ Error: The rules file '$RULES_FILE' was not found in this directory."
  echo "Please create it and add your audit rules before running this script."
  exit 1
fi

# --- Main Execution ---

echo "🚀 Starting auditd setup..."

# Step 1: Detect the package manager and install auditd.
if command -v apt-get &> /dev/null; then
    echo "🔎 Debian/Ubuntu based system detected. Using apt-get..."
    apt-get update -y > /dev/null 2>&1
    apt-get install auditd -y
    
elif command -v dnf &> /dev/null; then
    echo "🔎 RHEL/Fedora based system detected. Using dnf..."
    dnf install auditd -y
    
elif command -v yum &> /dev/null; then
    echo "🔎 RHEL/CentOS based system detected. Using yum..."
    yum install auditd -y
    
else
    echo "❌ Unsupported package manager. Please install auditd manually."
    exit 1
fi


echo "✅ auditd package installed successfully."

# Step 2: Enable the auditd service to start on boot.
systemctl enable auditd > /dev/null 2>&1
echo "✅ auditd service enabled on boot."

# Step 3: Copy the custom rules file into place.
echo "📋 Copying custom rules from '$RULES_FILE' to '$DEST_RULES_FILE'..."
cp "$RULES_FILE" "$DEST_RULES_FILE"
# Set proper permissions just in case.
chmod 640 "$DEST_RULES_FILE"

# Step 4: Restart the auditd service to load the new rules.
echo "🔄 Restarting auditd service to apply new configuration..."
systemctl restart auditd

# Step 5: Verify the service is active and list loaded rules.
if systemctl is-active --quiet auditd; then
    echo "✅ Verification successful! The auditd service is active and running."
    echo "🔎 Current rules loaded:"
    # Give the service a moment to settle before checking rules
    sleep 1
    auditctl -l
else
    echo "❌ Verification failed. The auditd service could not be started."
    echo "   Run 'journalctl -xe' or 'systemctl status auditd' for details."
    exit 1
fi

echo "🎉 Auditd setup complete!"
