#!/bin/bash

#
# This is a meme script to set up a 1.7.10 MC server in a competition...
# Yes, I'm too low on fucking sleep. I'm half way though my 2 weeks of finals.
# This is how I'm staying sane.
#
# Samuel Brucker 2025-2026
#



# Variables
MC_VERSION="1.7.10"
# Direct URL for Vanilla 1.7.10 Server Jar from Mojang's manifest
SERVER_URL="https://launcher.mojang.com/v1/objects/952438ac4e01b4d115c5fc38f891710c4941df29/server.jar"
INSTALL_DIR="/opt/mc_server_1.7.10"
MC_USER="mcadmin"
RAM_AMOUNT="3G"

#pretty colours yay <3
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' 

echo -e "${GREEN}Starting Minecraft $MC_VERSION Server Installer...${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Please run this script with sudo to install dependencies.${NC}"
  echo "Usage: sudo ./install_mc_1.7.10.sh"
  exit 1
fi

echo -e "${YELLOW}Detecting OS and installing Java 8 (Required for 1.7.10)...${NC}"

if command -v apt > /dev/null; then
    echo "Detected 'apt' package manager."
    apt-get update
    
    # Try to install OpenJDK 8 specifically. 
    # 1.7.10 will crash on Java 16/17+.
    if apt-cache show openjdk-8-jre-headless > /dev/null 2>&1; then
        apt-get install -y openjdk-8-jre-headless wget screen
    else
        echo -e "${RED}Error: openjdk-8-jre-headless not found in standard repos.${NC}"
        echo -e "${YELLOW}Attempting to install 'default-jre' as a fallback, but this may install Java 17+ which breaks MC 1.7.10.${NC}"
        echo "Press ENTER to continue anyway, or CTRL+C to cancel."
        read -r
        apt-get install -y default-jre wget screen
    fi

elif command -v dnf > /dev/null; then
    echo "Detected 'dnf' package manager."
    dnf install -y java-1.8.0-openjdk-headless wget screen

elif command -v yum > /dev/null; then
    echo "Detected 'yum' package manager."
    yum install -y java-1.8.0-openjdk-headless wget screen

else
    echo -e "${RED}Unsupported OS (No apt, dnf, or yum found). Please install Java 8, wget, and screen manually.${NC}"
    exit 1
fi

echo -e "${YELLOW}Setting up 'mcadmin' user and directory at: $INSTALL_DIR${NC}"

if ! id "$MC_USER" &>/dev/null; then
    echo "Creating user $MC_USER..."
    useradd -m -s /bin/bash "$MC_USER"
fi

mkdir -p "$INSTALL_DIR"
chown -R "$MC_USER":"$MC_USER" "$INSTALL_DIR"

cd "$INSTALL_DIR" || exit
echo -e "${YELLOW}Downloading Minecraft Server $MC_VERSION...${NC}"
sudo -u "$MC_USER" wget -O server.jar "$SERVER_URL"

if [ ! -f server.jar ]; then
    echo -e "${RED}Download failed! Exiting.${NC}"
    exit 1
fi

echo -e "${YELLOW}Accepting EULA...${NC}"
echo "eula=true" | sudo -u "$MC_USER" tee eula.txt > /dev/null


echo -e "${YELLOW}Creating startup script (start.sh)...${NC}"
START_SCRIPT="$INSTALL_DIR/start.sh"

cat <<EOF > "$START_SCRIPT"
#!/bin/bash
# Check if java 8 is the default, if not, try to find it
JAVA_CMD="java"

# Simple check to see if we are accidentally running a newer java version
VER=\$("\$JAVA_CMD" -version 2>&1 | grep -i version)
echo "System Java Version detected: \$VER"
echo "Starting Minecraft 1.7.10 with ${RAM_AMOUNT} RAM..."
echo "To exit the console without stopping the server, press Ctrl+A, then D."

# Launch command
"\$JAVA_CMD" -Xmx${RAM_AMOUNT} -Xms1G -jar server.jar nogui
EOF


chmod +x "$START_SCRIPT"
chown "$MC_USER":"$MC_USER" "$START_SCRIPT"


echo -e "Start the MC server with:"
echo -e "${YELLOW}sudo -u $MC_USER $START_SCRIPT${NC}"
