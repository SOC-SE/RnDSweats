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

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "The script is located in the directory:"
echo "$SCRIPT_DIR"
echo

cd $SCRIPT_DIR

echo "Setting up Auditd"
bash Auditd/auditdSetup.sh

echo "Configuring Yara rules"
bash Yara/yaraConfigure.sh

echo "Setting up the Wazuh agent"
bash Wazuh/linuxSetup.sh



echo "############################################################################"
echo "#                                                                          #"
echo "# Everything is set up and all good to go, Stage 1 is complete. Good luck! #"
echo "#                                                                          #"
echo "############################################################################"
