#!/usr/bin/env bash

#
#   Script taken and adapted from https://github.com/cyberuci/LOCS/tree/main/linux/linux-toolbox
#   Thank you CyberUCI, a bit of my time has been spared. <3
#
#   
#   Samuel Brucker 2025-2026
#


# Define Colors
BLUE='\033[0;34m'
NC='\033[0m' # No Color

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

#Install general packages
echo "${BLUE}Installing general packages: ${NC}"
if command_exists apt-get; then
    apt-get install -y coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

if command_exists yum; then
    yum install -y bash coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

if command_exists pacman; then
    pacman -S --noconfirm coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

if command_exists apk; then
    apk add coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi
echo "Essential packages stage done."


#Install Docker and Docker compose
echo "${BLUE}Installing Docker and Docker Compose: ${NC}"

# For Debian/Ubuntu/CentOS/RHEL, use the official convenience script
# This handles GPG keys, Repositories, and installs 'docker-ce' + 'docker-compose-plugin'
if command_exists apt-get || command_exists yum; then
    if ! command_exists docker; then
        echo "${BLUE}Downloading and running official Docker install script... ${NC}"
        curl -fsSL https://get.docker.com | sh
    else
        echo "${BLUE}Docker command already exists. Skipping installation. ${NC}"
    fi
fi

# For Arch Linux
if command_exists pacman; then
    pacman -S --noconfirm docker docker-compose
fi

# For Alpine Linux
if command_exists apk; then
    apk add docker docker-compose
fi

echo "${BLUE}Docker installation stage done. ${NC}"