#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# calderaSetup.sh
#
# This script installs MITRE Caldera if not present, or starts the
# service if it is
#
# Samuel Brucker 2025 (with a sprinkle of AI)
#

# --- Sanity Checks ---

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

# 2. Check if the OS is Debian
source /etc/os-release
if [ "$ID" != "debian" ]; then
  echo "Warning: This script is designed for Debian."
  echo "You are running on '$PRETTY_NAME'."
  read -p "Do you want to proceed anyway? (y/N): " response
  if [[ ! "$response" =~ ^[yY]$ ]]; then
    echo "Aborting operation."
    exit 1
  fi
fi

#Get the easy dependencies
apt update
apt install curl ca-certificates python3 python3-pip ibxml2-dev libxslt-dev python3-dev python3-lxml

#Install NodeJS
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
apt install -y nodejs

#Install GoLang
wget https://go.dev/dl/go1.17.13.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.17.13.linux-amd64.tar.gz

 # Set up the PATH for all users (requires re-login to take effect)
  if ! grep -q "/usr/local/go/bin" /etc/profile; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
  fi

  echo "✅ Go installation successful."
  # Source the profile to make 'go' command available immediately in this script
  export PATH=$PATH:/usr/local/go/bin


git clone https://github.com/mitre/caldera.git --recursive /opt/caldera
cd /opt/caldera
sed -i '/^lxml/ s/^/#/' requirements.txt
pip3 install --break-system-packages -r requirements.txt
python3 server.py --insecure --build > /var/caldera.log 2.&1 &
