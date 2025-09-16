#!/bin/bash

# This script installs Docker and Apache Guacamole on a Debian 13 system.
# It should be run with root privileges (e.g., using sudo).

# --- Script Configuration ---
DB_PASSWORD="Changeme1!" # Please change this to a secure password
INSTALL_DIR="/opt/guacamole"

# --- 1. System Update and Prerequisite Installation ---
echo "Updating system packages and installing prerequisites..."
apt-get update
apt-get install -y ca-certificates curl gnupg

# --- 2. Docker Installation ---
echo "Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update

# Install Docker Engine, CLI, and Containerd
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify Docker installation
if ! docker --version &> /dev/null; then
    echo "Docker installation failed. Exiting."
    exit 1
fi
echo "Docker installed successfully."

# --- 3. Set Up Guacamole Environment ---
echo "Setting up Guacamole environment in $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
if [ $? -ne 0 ]; then
    echo "Failed to create directory $INSTALL_DIR. Exiting."
    exit 1
fi

# Create a dedicated Docker network
docker network create guacamole-net &> /dev/null
echo "Docker network 'guacamole-net' created."

# --- 4. Initialize PostgreSQL Database ---
echo "Initializing PostgreSQL database for Guacamole..."
docker run --rm guacamole/guacamole /opt/guacamole/bin/initdb.sh --postgres > "$INSTALL_DIR/initdb.sql"
if [ $? -ne 0 ]; then
    echo "Failed to generate initdb.sql. Exiting."
    exit 1
fi
echo "Database initialization script created."

# --- 5. Launch Docker Containers ---

# Start guacd (the Guacamole proxy daemon)
echo "Starting guacd container..."
docker run --name guacd \
    --network guacamole-net \
    -d --restart=always \
    guacamole/guacd

# Start PostgreSQL database container
echo "Starting PostgreSQL container..."
docker run --name guacamole-db \
    --network guacamole-net \
    -v "$INSTALL_DIR/initdb.sql:/docker-entrypoint-initdb.d/init.sql" \
    -e POSTGRES_DB=guacamole_db \
    -e POSTGRES_USER=guacamole_user \
    -e POSTGRES_PASSWORD="$DB_PASSWORD" \
    -d --restart=always \
    postgres:15-alpine

# Wait a moment for the database to initialize
echo "Waiting for the database to initialize... (15 seconds)"
sleep 15

# Start Guacamole web client
echo "Starting Guacamole web client container..."
docker run --name guacamole \
    --network guacamole-net \
    --link guacd:guacd \
    --link guacamole-db:postgres \
    -e GUACAMOLE_JDBC_HOSTNAME=guacamole-db \
    -e GUACAMOLE_JDBC_DATABASE=guacamole_db \
    -e GUACAMOLE_JDBC_USERNAME=guacamole_user \
    -e GUACAMOLE_JDBC_PASSWORD="$DB_PASSWORD" \
    -p 8080:8080/tcp \
    -d --restart=always \
    guacamole/guacamole

# --- 6. Final Instructions ---
echo "---------------------------------------------------------"
echo "✅ Guacamole installation is complete!"
echo ""
echo "You can now access the Guacamole web interface at:"
echo "http://<your-server-ip>:8080/guacamole/"
echo ""
echo "Default login credentials:"
echo "Username: guacadmin"
echo "Password: guacadmin"
echo ""
echo "🚨 IMPORTANT: Please log in immediately and change the default password."
echo "---------------------------------------------------------"
