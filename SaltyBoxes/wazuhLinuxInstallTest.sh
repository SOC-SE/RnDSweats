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

hostname = $(hostname -f)

echo "$pwd" 2>&1

cd /etc/runtl

echo "Setting up Auditd"
bash Auditd/auditdSetup.sh

echo "Installing Yara"
bash Yara/yaraInstall.sh

echo "Configuring Yara rules"
bash Yara/yaraConfigure.sh

echo "Setting up the Wazuh agent"
bash Wazuh/linuxSetup.sh


echo "Wazuh Agent installation and configuration for $hostname comeplete." 2>&1



