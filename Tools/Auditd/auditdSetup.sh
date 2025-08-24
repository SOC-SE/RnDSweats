#!/bin/bash

# ==============================================================================
# CCDC Development - ROBUST Cross-Distribution Auditd Installer
#
# Description: Installs auditd, enables the service, copies a local 
#              audit.rules file, fixes SELinux context, and explicitly
#              loads the new rules. This version is hardened to work on
#              CentOS 7 and modern Fedora/RHEL systems.
# Author:      CCDC Development
# Version:     2.0
# ==============================================================================

# --- Configuration ---
RULES_FILE="audit.rules"
DEST_RULES_FILE="/etc/audit/rules.d/99-custom.rules"

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi
if [ ! -f "$RULES_FILE" ]; then
  echo "❌ Error: The rules file '$RULES_FILE' was not found in this directory."
  exit 1
fi

# --- Main Execution ---
echo "🚀 Starting robust auditd setup..."

# Step 1: Install auditd
echo "----------------------------------------"
echo "STEP 1: Installing auditd package..."
if command -v apt-get &> /dev/null; then
    apt-get update -y > /dev/null 2>&1
    apt-get install auditd -y
    
elif command -v dnf &> /dev/null; then
    dnf install auditd -y
    
elif command -v yum &> /dev/null; then
    yum install auditd -y
    
else
    echo "❌ Unsupported package manager. Please install auditd manually."
    exit 1
fi
echo "✅ auditd package installed."

# Step 2: Enable the auditd service
echo "----------------------------------------"
echo "STEP 2: Enabling auditd service on boot..."
systemctl enable auditd > /dev/null 2>&1
echo "✅ auditd service enabled."

# Step 3: Copy the custom rules file
echo "----------------------------------------"
echo "STEP 3: Copying custom rules to $DEST_RULES_FILE..."
cp -f "$RULES_FILE" "$DEST_RULES_FILE"
chmod 640 "$DEST_RULES_FILE"
echo "✅ Rules file copied."

# Step 4: Fix SELinux Context (CRITICAL FOR FEDORA/RHEL)
echo "----------------------------------------"
echo "STEP 4: Restoring SELinux context on rules file..."
# Check if restorecon command exists before running it
if command -v restorecon &> /dev/null; then
    restorecon -v "$DEST_RULES_FILE"
    echo "✅ SELinux context restored."
else
    echo "🔎 'restorecon' not found, skipping. (This is normal on non-SELinux systems like Debian/Ubuntu)."
fi

# Step 5: Explicitly Load Rules (CRITICAL FOR CENTOS 7)
echo "----------------------------------------"
echo "STEP 5: Forcing the kernel to load the new rules now..."
# This command reads all files in rules.d and loads them.
augenrules --load
if [ $? -ne 0 ]; then
    echo "❌ FAILED to load audit rules. There is likely a syntax error in your '$RULES_FILE'."
    exit 1
fi
echo "✅ Rules loaded into the kernel successfully."

# Step 6: Restart the daemon and verify
echo "----------------------------------------"
echo "STEP 6: Restarting the auditd daemon and verifying..."
systemctl restart auditd
sleep 1 # Give the service a moment to stabilize

if systemctl is-active --quiet auditd; then
    echo "✅ Verification successful! The auditd service is active."
    echo "🔎 Current rules loaded in kernel:"
    auditctl -l
else
    echo "❌ Verification failed. The auditd service could not be started."
    exit 1
fi

echo ""
echo "🎉 Auditd setup complete!"
