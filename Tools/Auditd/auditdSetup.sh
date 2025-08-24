#!/bin/bash

# ==============================================================================
# CCDC Development - Wazuh-Compatible Cross-Distribution Auditd Installer
#
# Description: Installs auditd, copies a local audit.rules file, removes
#              the Wazuh-incompatible '-a never,task' rule, fixes SELinux
#              context, and explicitly loads the new rules.
# Author:      CCDC Development
# Version:     2.1
# ==============================================================================

# --- Configuration ---
RULES_FILE="audit.rules"
DEST_RULES_FILE="/etc/audit/rules.d/99-custom.rules"
# Rule to be removed for Wazuh compatibility
INCOMPATIBLE_RULE="-a never,task"

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
echo "🚀 Starting robust, Wazuh-compatible auditd setup..."

# Step 1: Install auditd
echo "----------------------------------------"
echo "STEP 1: Installing auditd package..."
if command -v apt-get &> /dev/null; then
    apt-get update -y > /dev/null 2>&1
    apt-get install auditd audispd-plugins -y
    
elif command -v dnf &> /dev/null; then
    dnf install auditd audispd-plugins -y
    
elif command -v yum &> /dev/null; then
    yum install auditd audispd-plugins -y
    
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

# Step 4: Sanitize Rules for Wazuh (CRITICAL FOR WAZUH)
echo "----------------------------------------"
echo "STEP 4: Removing Wazuh-incompatible rule: '$INCOMPATIBLE_RULE'..."
# Use sed to find the exact line and delete it in-place.
sed -i "/^${INCOMPATIBLE_RULE}$/d" "$DEST_RULES_FILE"
echo "✅ Rules file sanitized for Wazuh."

# Step 5: Fix SELinux Context (CRITICAL FOR FEDORA/RHEL)
echo "----------------------------------------"
echo "STEP 5: Restoring SELinux context on rules file..."
if command -v restorecon &> /dev/null; then
    restorecon -v "$DEST_RULES_FILE"
    echo "✅ SELinux context restored."
else
    echo "🔎 'restorecon' not found, skipping. (This is normal on non-SELinux systems)."
fi

# Step 6: Explicitly Load Rules (CRITICAL FOR CENTOS 7)
echo "----------------------------------------"
echo "STEP 6: Forcing the kernel to load the new rules now..."
augenrules --load
if [ $? -ne 0 ]; then
    echo "❌ FAILED to load audit rules. There is likely a syntax error in your '$RULES_FILE'."
    exit 1
fi
echo "✅ Rules loaded into the kernel successfully."

# Step 7: Restart the daemon and verify
echo "----------------------------------------"
echo "STEP 7: Restarting the auditd daemon and verifying..."
systemctl restart auditd
sleep 1 # Give the service a moment to stabilize

if systemctl is-active --quiet auditd; then
    echo "✅ Verification successful! The auditd service is active."
    echo "🔎 To see the current rules loaded in kernel, run this command:"
    echo "sudo auditctl -l"
else
    echo "❌ Verification failed. The auditd service could not be started."
    exit 1
fi

echo ""
echo "🎉 Wazuh-compatible auditd setup complete!"
