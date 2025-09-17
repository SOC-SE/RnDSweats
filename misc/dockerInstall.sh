#!/bin/bash

# This script automates the installation of Docker on Debian and Red Hat-based Linux machines.

# Exit immediately if a command exits with a non-zero status.
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo."
  exit 1
fi

# Function to install Docker on Debian-based systems
install_docker_debian() {
    echo "Detected Debian-based system. Installing Docker..."
    apt-get update
    apt-get install -y ca-certificates curl gnupg lsb-release

    # Add Docker’s official GPG key
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Set up the repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    echo "Docker installed successfully on Debian-based system."
}

# Function to install Docker on RHEL and its clones (CentOS, Fedora, AlmaLinux, Rocky Linux)
install_docker_rhel_clones() {
    echo "Detected RHEL-based system ($ID). Installing Docker..."
    yum install -y yum-utils
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    echo "Docker installed successfully on RHEL-based system."
}

# Function to install Docker on Oracle Linux
install_docker_oracle() {
    echo "Detected Oracle Linux. Installing Docker..."
    yum install -y yum-utils
    # On Oracle Linux, the container-tools module may need to be disabled.
    if yum module list --enabled | grep -q 'container-tools'; then
        echo "Disabling container-tools module..."
        yum module disable -y container-tools
    fi
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    echo "Docker installed successfully on Oracle Linux."
}

# Detect the Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "debian" || "$ID_LIKE" == "debian" || "$ID" == "ubuntu" ]]; then
        install_docker_debian
    elif [[ "$ID" == "ol" ]]; then
        install_docker_oracle
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID" == "fedora" || "$ID" == "almalinux" || "$ID" == "rocky" || "$ID_LIKE" == "rhel" || "$ID_LIKE" == "fedora" ]]; then
        install_docker_rhel_clones
    else
        echo "Unsupported Linux distribution: $ID. This script only supports Debian and Red Hat-based systems."
        exit 1
    fi
else
    echo "Cannot determine Linux distribution. /etc/os-release not found."
    exit 1
fi

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Add the current user to the docker group
if [ -n "$SUDO_USER" ]; then
    usermod -aG docker "$SUDO_USER"
    echo "Added user '$SUDO_USER' to the docker group."
    echo "You may need to log out and log back in for the group changes to take effect."
fi

echo "Run 'docker run hello-world' to test your installation."