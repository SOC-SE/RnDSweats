#!/bin/bash
#
# We all know how permanent the most temporary solutions are
#
# Samuel Brucker 2025-2026
#

# Make sure this is being ran as sudo
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi


apt install curl -y

curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -so wazuh-passwords-tool.sh https://packages.wazuh.com/4.14/wazuh-passwords-tool.sh

bash wazuh-install.sh -a

#mv Tools/Wazuh/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
#mv Tools/Wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
#mv Tools/Wazuh/ossec.conf /var/ossec/etc/ossec.conf

cd Tools/Wazuh/Configs/
bash setConfigs.sh

#cd ../../../
bash wazuh-passwords-tool.sh -u admin -p Changeme1*
