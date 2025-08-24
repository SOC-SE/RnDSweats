#    Setup file to automate all of our tooling for the individual servers and endpoints
#
#    Created by Samuel Brucker, 2025-2026
#
#
#

# Make sure this is being ran as sudo
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

echo "Setting up auditd"
bash Auditd/auditdSetup.sh

if systemctl is-active --quiet auditd; then
    echo "✅ Verification successful! The auditd service is active."
    echo "🔎 To see the current rules loaded in kernel, run this command:"
    echo "sudo auditctl -l"
else
    echo "❌ Verification failed. The auditd service could not be started."
    exit 1
fi


echo "Setting up the Wazuh agent"
bash Wazuh/linuxSetup.sh

if systemctl is-active --quiet wazuh-agent; then
    echo "✅ Verification successful! The Wazuh Agent service is active."
else
    echo "❌ Verification failed. The Wazuh Agent service could not be started."
    exit 1
fi


echo "Everything is set up and all good to go, Stage 1 is complete. Good luck!"
