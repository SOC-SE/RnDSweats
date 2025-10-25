#!/bin/bash
#
# Distro-Agnostic Docker & Docker Compose Installer
#
# This script detects the package manager (apt, dnf, yum) and installs:
# 1. Docker Engine (docker-ce)
# 2. Docker Compose (the modern 'docker-compose-plugin')
#
# MUST BE RUN AS ROOT OR WITH SUDO.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Functions ---

# Function to install Docker and Compose using APT (Ubuntu/Debian)
install_with_apt() {
  echo "Detected APT. Installing Docker for Ubuntu/Debian..."
  
  # Ensure the environment is non-interactive
  export DEBIAN_FRONTEND=noninteractive
  
  # 1. Set up prerequisites
  apt update
  apt install -y ca-certificates curl gnupg
  
  # 2. Add Docker's official GPG key
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  
  # 3. Set up the Docker repository
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
    
  # 4. Install Docker Engine and Compose
  apt update
  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

# Function to install Docker and Compose using DNF (Fedora, Oracle Linux 9, RHEL 9)
install_with_dnf() {
  echo "Detected DNF. Installing Docker for RHEL family..."
  
  # 1. Get OS ID to set correct repo
  if [ ! -f /etc/os-release ]; then
    echo "Error: /etc/os-release not found. Cannot determine DNF repository."
    exit 1
  fi
  . /etc/os-release
  
  local repo_url=""
  if [ "$ID" = "fedora" ]; then
    repo_url="https://download.docker.com/linux/fedora/docker-ce.repo"
  else
    # For Oracle Linux, RHEL, CentOS Stream, etc.
    repo_url="https://download.docker.com/linux/centos/docker-ce.repo"
  fi
  
  # 2. Set up the Docker repository
  dnf -y install dnf-plugins-core
  dnf config-manager --add-repo "$repo_url"
  
  # 3. Install Docker Engine and Compose
  # --allowerasing is needed on RHEL/Oracle to replace podman/buildah packages
  dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin --allowerasing
}

# Function to install Docker and Compose using YUM (CentOS 7, older RHEL)
install_with_yum() {
  echo "Detected YUM. Installing Docker for RHEL family (legacy)..."
  
  # 1. Set up prerequisites
  yum install -y yum-utils
  
  # 2. Set up the Docker repository (uses CentOS repo)
  yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  
  # 3. Install Docker Engine
  yum install -y docker-ce docker-ce-cli containerd.io
  
  echo "Installing Docker Compose (standalone binary for YUM-based systems)..."
  # YUM-based systems are older, so we install the v1 'docker-compose' binary
  # as the plugin is not officially supported on all of them.
  
  # Get latest v1 release (v1 is deprecated, but this is the legacy method)
  COMPOSE_V1_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases | grep '"tag_name":' | grep -v 'v2' | grep -v 'rc' | head -n 1 | awk -F'"' '{print $4}')
  
  if [ -z "$COMPOSE_V1_VERSION" ]; then
    echo "Warning: Could not find latest docker-compose v1 release. Defaulting to 1.29.2"
    COMPOSE_V1_VERSION="1.29.2"
  fi
  
  echo "Installing docker-compose version $COMPOSE_V1_VERSION..."
  DEST_PATH="/usr/local/bin/docker-compose"
  curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_V1_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o "$DEST_PATH"
  chmod +x "$DEST_PATH"
}

start_docker_service() {
  echo "Starting and enabling Docker service..."
  systemctl start docker
  systemctl enable docker
  echo "Docker service started and enabled."
}

# --- Main Script ---

main() {
  # Check for root privileges
  if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo or as root."
    exit 1
  fi
  
  # 1. Detect Package Manager and Install
  if command -v apt &> /dev/null; then
    install_with_apt
    
  elif command -v dnf &> /dev/null; then
    install_with_dnf
    
  elif command -v yum &> /dev/null; then
    install_with_yum
    
  else
    echo "Error: Could not find apt, dnf, or yum."
    echo "This script supports Debian/Ubuntu and RHEL/Fedora/Oracle families."
    exit 1
  fi
  
  # 2. Start and Enable Docker
  start_docker_service
  
  # 3. Final Message
  echo "-------------------------------------------------"
  echo "Docker installation complete."
  echo ""
  echo "NOTE: The modern Docker Compose is run as a plugin."
  echo "Use 'docker compose' (with a space) instead of 'docker-compose'."
  echo ""
  echo "Run 'docker --version' and 'docker compose version' to verify."
  echo "You may need to log out and log back in to run docker commands as a non-root user."
  echo "(To add current user: sudo usermod -aG docker \$USER)"
}

# Run the main function
main
