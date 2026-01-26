#!/bin/sh
#
# Alpine Suricata Setup via Docker
# Sets up Suricata IDS in a Docker container with NFQUEUE mode
#
# Requires: docker, docker-compose, git
# Tested on: Alpine 3.18+
#
# Samuel Brucker 2025-2026

set -eu

# --- Pre-checks ---
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

# Check for required commands
for cmd in docker git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is required but not installed."
        exit 1
    fi
done

# Check if docker compose is available (v2 syntax)
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "ERROR: docker compose or docker-compose is required."
    exit 1
fi

# --- Setup ---
WORKDIR="${WORKDIR:-/opt/suricata}"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Clone or update the docker-suricata repository
if [ -d "docker-suricata" ]; then
    echo "[*] docker-suricata already exists, pulling updates..."
    cd docker-suricata
    git pull || echo "Warning: Could not pull updates"
else
    echo "[*] Cloning docker-suricata repository..."
    git clone https://github.com/julienyvenat/docker-suricata.git ./docker-suricata
    cd docker-suricata
fi

# Fix the Dockerfile for modern Alpine (py-pip -> py3-pip)
DOCKERFILE="alpine/Dockerfile/Dockerfile"
if [ -f "$DOCKERFILE" ]; then
    echo "[*] Patching Dockerfile for Alpine compatibility..."
    # Fix python package names
    sed -i 's/RUN apk add python py-pip/RUN apk add python3 py3-pip/g' "$DOCKERFILE"
    # Fix pip install command for externally managed environments
    sed -i 's/RUN pip install suricata-update/RUN pip3 install --break-system-packages suricata-update/g' "$DOCKERFILE"
else
    echo "Warning: Dockerfile not found at $DOCKERFILE"
fi

# Start Suricata container
echo "[*] Building and starting Suricata container..."
$COMPOSE_CMD up -d --build --force-recreate

# Wait for container to be ready
echo "[*] Waiting for container to start..."
sleep 5

# Verify container is running
if docker ps | grep -q suricata; then
    echo "[+] Suricata container is running."
else
    echo "[-] Warning: Suricata container may not have started correctly."
    echo "    Check with: docker ps -a"
fi

# Add iptables NFQUEUE rules for inline IDS mode
echo "[*] Adding iptables NFQUEUE rules..."
# Remove existing NFQUEUE rules first to avoid duplicates
iptables -D INPUT -j NFQUEUE 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE 2>/dev/null || true

# Add new rules at the beginning of chains
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE
iptables -I FORWARD -j NFQUEUE

echo "[+] Suricata setup complete."
echo "    Logs: docker logs suricata"
echo "    Config: $WORKDIR/docker-suricata/"
