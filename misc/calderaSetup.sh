#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

##
# This script automates the installation of MITRE Caldera via Docker on Debian 13.
# It checks for the correct OS, installs dependencies, and configures the container
# to run on startup with the name "caldera".
##

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
    echo "Aborting installation."
    exit 1
  fi
fi

# --- Installation Steps ---

echo "✅ Starting Caldera installation..."

# 1. Install Docker, Git, and Docker Compose
echo "📦 Installing dependencies (Docker, Git, Docker Compose)..."
apt-get update
apt-get install -y ca-certificates curl git docker.io docker-compose

# 2. Enable and start the Docker service
echo "🚀 Enabling and starting Docker service..."
systemctl enable docker --now

# 3. Clone the Caldera repository
if [ -d "/opt/caldera" ]; then
  echo "✅ Caldera directory already exists. Skipping clone."
else
  echo "Cloning Caldera repository into /opt/caldera..."
  git clone https://github.com/mitre/caldera.git --recursive /opt/caldera
fi

# 4. Configure and build the Docker container
echo "🛠️ Configuring and building the Caldera container..."
cd /opt/caldera

# Modify the docker-compose file to set the container name and restart policy
echo "📝 Setting container name to 'caldera' and restart policy to 'unless-stopped'..."
sed -i '/image: caldera:server/a \ \ \ \ container_name: caldera\n    restart: unless-stopped' docker-compose.yml

# Build and start the container in detached mode
docker-compose up --build -d

# --- Finalization ---
echo ""
echo "🎉 Caldera installation complete!"
echo "The 'caldera' container is running in the background and will restart on boot."
echo ""
echo "Access the web interface at: http://<your_server_ip>:8888"
echo "Default credentials are:"
echo "  - Username: admin"
echo "  - Password: admin"
echo ""
echo "Use 'docker logs -f caldera' to view the application logs."
