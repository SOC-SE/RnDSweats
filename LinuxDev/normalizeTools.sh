#!/usr/bin/env bash

#
#   Script taken and adapted from https://github.com/cyberuci/LOCS/tree/main/linux/linux-toolbox
#   Thank you CyberUCI, a bit of my time has been spared. <3
#
#   I'm lazy, so yes, Gemini was used to add on the full docker portion, adapated from a previous script my team made.
#
#   Samuel Brucker 2025-2026
#


# Define Colors
BLUE='\033[0;34m'
NC='\033[0m' # No Color

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

# --- Essential Packages ---
echo -e "${BLUE}Installing essential packages:${NC}"
if command_exists apt-get; then
    apt-get update -y
    apt-get install -y coreutils net-tools iproute2 iptables bash curl git vim wget grep tar jq gpg nano
fi

if command_exists yum; then
    yum install -y bash coreutils net-tools iproute2 iptables curl git vim wget grep tar jq gpg nano
fi

if command_exists pacman; then
    pacman -S --noconfirm coreutils net-tools iproute2 iptables bash curl git vim wget grep tar jq gpg nano
fi

if command_exists apk; then
    apk add coreutils net-tools iproute2 iptables bash curl git vim wget grep tar jq gpg nano
fi
echo -e "${BLUE}Essential packages stage done.${NC}"


# ---------------------------------------------------------
# Docker
# ---------------------------------------------------------
echo -e "${BLUE}Installing Docker and Docker Compose:${NC}"

if command_exists docker; then
    echo -e "${BLUE}Docker is already installed. Skipping installation.${NC}"
else
    # --- Debian / Ubuntu Logic ---
    if command_exists apt-get; then
        echo -e "${BLUE}Detected apt (Debian/Ubuntu). Configuring official Docker repo...${NC}"
        
        # 1. Remove old packages
        apt-get remove -y docker docker-engine docker.io containerd runc || true
        
        # 2. Install prerequisites
        apt-get update -y
        apt-get install -y ca-certificates curl gnupg
        
        # 3. Add Docker GPG key
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        # 4. Set up the repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null
          
        # 5. Install Docker Engine
        apt-get update -y
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi

    # --- RHEL / CentOS / Oracle Linux Logic ---
    if command_exists dnf || command_exists yum; then
        echo -e "${BLUE}Detected dnf/yum (RHEL/CentOS/Oracle). Configuring Docker repo...${NC}"
        
        # Determine command to use (dnf preferred, fallback to yum)
        if command_exists dnf; then CMD="dnf"; else CMD="yum"; fi

        # 1. Remove old packages (ignore errors if not installed)
        $CMD remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine || true

        # 2. Install utils and config-manager
        $CMD install -y dnf-plugins-core yum-utils

        # 3. Add the repo (Using CentOS repo as per your working script logic)
        # This is standard for RHEL derivatives like Oracle Linux
        if command_exists config-manager; then
             config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        elif command_exists dnf; then
             dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        else
             yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        fi

        # 4. Install Docker Engine
        $CMD install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi

    # --- Arch Linux Logic ---
    if command_exists pacman; then
        echo -e "${BLUE}Detected pacman. Installing from community repo...${NC}"
        pacman -S --noconfirm docker docker-compose
    fi

    # --- Alpine Linux Logic ---
    if command_exists apk; then
        echo -e "${BLUE}Detected apk. Installing from community repo...${NC}"
        apk add docker docker-compose
    fi
fi

# --- Post-Installation Configuration ---
if command_exists systemctl; then
    echo -e "${BLUE}Enabling and starting Docker service...${NC}"
    systemctl start docker
    systemctl enable docker
fi

# Add current user (and sudo user if exists) to docker group
# This avoids needing 'sudo' for every docker command
echo -e "${BLUE}Configuring permissions...${NC}"
if getent group docker > /dev/null; then
    usermod -aG docker "$(whoami)" || true
    if [ -n "${SUDO_USER}" ]; then
        usermod -aG docker "$SUDO_USER" || true
    fi
fi

echo -e "${BLUE}Docker installation stage done.${NC}"
