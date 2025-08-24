# Make sure this is being ran as sudo
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi


apt install curl -y

curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh

bash wazuh-install -a

bash wazuh-passwords-tool.sh -u admin -p Changeme1*
