#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# calderaSetup.sh
#
# This script installs MITRE Caldera if not present, or starts the
# server if it is installed but not running.
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

# --- Main Logic ---

# Check if Caldera appears to be installed
if [ -d "/opt/caldera" ]; then
  echo "✅ Caldera directory found."
  # Check if a service is already listening on port 8888
  if ss -tuln | grep -q ':8888'; then
    echo "✅ Caldera is already installed and a service is running on port 8888."
    exit 0
  else
    # If installed but not running, start the server
    echo "Caldera is installed but not running. Starting the server..."
    cd /opt/caldera
    nohup python3 server.py --insecure > /var/caldera.log 2>&1 &
    echo "🚀 Caldera server started in the background."
  fi
else
  # --- Full Installation ---
  echo "➡️ Caldera not found. Starting full installation..."

  # 1. Install all dependencies in one go
  echo "📦 Installing dependencies..."
  apt-get update
  apt-get install -y curl ca-certificates python3 python3-pip libxml2-dev libxslt-dev python3-dev python3-lxml git

  # 2. Install NodeJS
  echo "Installing NodeJS..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  apt-get install -y nodejs

  # 3. Install GoLang
  echo "Installing Go..."
  GO_TARBALL="go1.17.13.linux-amd64.tar.gz"
  wget "https://go.dev/dl/$GO_TARBALL"
  tar -C /usr/local -xzf "$GO_TARBALL"
  rm "$GO_TARBALL" # Clean up downloaded file

  # Set up Go PATH for all users
  if ! grep -q "/usr/local/go/bin" /etc/profile; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
  fi
  export PATH=$PATH:/usr/local/go/bin # Make 'go' available for this script

  # 4. Clone and set up Caldera
  echo "Cloning Caldera and installing Python packages..."
  git clone https://github.com/mitre/caldera.git --recursive /opt/caldera
  cd /opt/caldera
  
  # Comment out lxml to use the system-installed version
  sed -i '/^lxml/ s/^/#/' requirements.txt
  
  pip3 install --break-system-packages --ignore-installed -r requirements.txt

  # 5. Start the Caldera server
  echo "🚀 Starting Caldera server for the first time..."
  # CORRECTED: Removed the invalid '--build' flag and used 'nohup'
  nohup python3 server.py --insecure > /var/caldera.log 2>&1 &
  echo "🎉 Caldera installation complete!"

fi

# --- Finalization ---
echo ""
echo "Access the web interface at: http://<your_server_ip>:8888"
echo "Check the logs with: tail -f /var/caldera.log"
