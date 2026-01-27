#!/bin/bash
set -euo pipefail
#
#    Setup file to automate all of our tooling for the individual servers and endpoints
#
#    Created by Samuel Brucker, 2025-2026
#

# Make sure this is being ran as sudo
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root or with sudo. Please try again."
  exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "The script is located in the directory:"
echo "$SCRIPT_DIR"
echo

cd "$SCRIPT_DIR"

# Define paths to related scripts
AUDITD_SCRIPT="$SCRIPT_DIR/../auditd/auditdSetup.sh"
YARA_SCRIPT="$SCRIPT_DIR/../../utilities/yara/yaraConfigure.sh"
WAZUH_SCRIPT="$SCRIPT_DIR/linuxSetup.sh"

echo "Setting up Auditd"
if [[ -f "$AUDITD_SCRIPT" ]]; then
    bash "$AUDITD_SCRIPT"
else
    echo "[WARN] Auditd script not found at $AUDITD_SCRIPT, skipping."
fi

echo "Configuring Yara rules"
if [[ -f "$YARA_SCRIPT" ]]; then
    bash "$YARA_SCRIPT"
else
    echo "[WARN] Yara script not found at $YARA_SCRIPT, skipping."
fi

echo "Setting up the Wazuh agent"
if [[ -f "$WAZUH_SCRIPT" ]]; then
    bash "$WAZUH_SCRIPT"
else
    echo "[ERROR] Wazuh setup script not found at $WAZUH_SCRIPT"
    exit 1
fi



echo "############################################################################"
echo "#                                                                          #"
echo "# Everything is set up and all good to go, Stage 1 is complete. Good luck! #"
echo "#                                                                          #"
echo "############################################################################"
