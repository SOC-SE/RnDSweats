#!/bin/bash

# ==============================================================================
# Minecraft 1.7.10 Server Installer (Debian/Ubuntu & RHEL/CentOS)
# ==============================================================================

# Variables
MC_VERSION="1.7.10"
SERVER_URL="https://launcher.mojang.com/v1/objects/952438ac4e01b4d115c5fc38f891710c4941df29/server.jar"
LOG4J_URL="https://launcher.mojang.com/v1/objects/4bb89a97a66f570bddc5592c671d46345a060f08/log4j2_17-111.xml"
INSTALL_DIR="/opt/mc_server_1.7.10"
MC_USER="mcadmin"
RAM_AMOUNT="3G"

# Colors for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Minecraft $MC_VERSION Server Installer...${NC}"

# 1. Check for Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root (sudo).${NC}"
  exit 1
fi

# 2. Detect OS and Install Dependencies
echo -e "${YELLOW}Detecting OS and installing dependencies...${NC}"

if command -v apt > /dev/null; then
    # --- Debian/Ubuntu ---
    echo "Detected 'apt' package manager."
    apt-get update
    # Install dependencies. openjdk-8 might be missing on very new Debians, fallback to default if needed
    if apt-cache show openjdk-8-jre-headless > /dev/null 2>&1; then
        apt-get install -y openjdk-8-jre-headless wget screen
    else
        echo -e "${YELLOW}OpenJDK 8 not found. Installing default-jre (Warning: MC 1.7.10 might not work with Java 17+).${NC}"
        apt-get install -y default-jre wget screen
    fi

elif command -v dnf > /dev/null; then
    # --- RHEL 8/9 / Fedora / Rocky ---
    echo "Detected 'dnf' package manager."
    # RHEL 9 requires EPEL for 'screen'
    echo "Installing epel-release to ensure 'screen' is available..."
    dnf install -y epel-release
    dnf clean all
    
    echo "Installing Java 8, wget, and screen..."
    dnf install -y java-1.8.0-openjdk-headless wget screen

elif command -v yum > /dev/null; then
    # --- Older RHEL / CentOS ---
    echo "Detected 'yum' package manager."
    yum install -y epel-release
    yum install -y java-1.8.0-openjdk-headless wget screen

else
    echo -e "${RED}Error: No supported package manager found (apt, dnf, yum).${NC}"
    exit 1
fi

# 3. Verify Dependencies (CRITICAL STEP)
echo -e "${YELLOW}Verifying installation...${NC}"

if ! command -v wget > /dev/null; then
    echo -e "${RED}Error: 'wget' failed to install. Please install it manually.${NC}"
    exit 1
fi

if ! command -v screen > /dev/null; then
    echo -e "${RED}Error: 'screen' failed to install. Please install it manually.${NC}"
    exit 1
fi

if ! command -v java > /dev/null; then
    echo -e "${RED}Error: 'java' command not found. Checking for specific binary paths...${NC}"
    # Try to find java 8 specifically if 'java' alias isn't set
    if [ -f "/usr/lib/jvm/jre-1.8.0-openjdk/bin/java" ]; then
        echo "Found Java at /usr/lib/jvm/jre-1.8.0-openjdk/bin/java"
        SYSTEM_JAVA="/usr/lib/jvm/jre-1.8.0-openjdk/bin/java"
    elif [ -f "/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java" ]; then
        echo "Found Java at /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
        SYSTEM_JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
    else
        echo -e "${RED}CRITICAL ERROR: Java 8 could not be found. Installation aborted.${NC}"
        exit 1
    fi
else
    SYSTEM_JAVA="java"
fi

# 4. Create User and Setup Directory
echo -e "${YELLOW}Setting up '$MC_USER' user and directory at: $INSTALL_DIR${NC}"

if ! id "$MC_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$MC_USER"
fi

mkdir -p "$INSTALL_DIR"
chown -R "$MC_USER":"$MC_USER" "$INSTALL_DIR"

# 5. Download Files
cd "$INSTALL_DIR" || exit
echo -e "${YELLOW}Downloading Server Files...${NC}"

sudo -u "$MC_USER" wget -O server.jar "$SERVER_URL"
sudo -u "$MC_USER" wget -O log4j2_17-111.xml "$LOG4J_URL"

if [ ! -f server.jar ]; then
    echo -e "${RED}Error: Server JAR failed to download.${NC}"
    exit 1
fi

# 6. EULA
echo "eula=true" | sudo -u "$MC_USER" tee eula.txt > /dev/null

# 7. Create Start Script
START_SCRIPT="$INSTALL_DIR/start.sh"
echo -e "${YELLOW}Creating start script...${NC}"

cat <<EOF > "$START_SCRIPT"
#!/bin/bash
JAVA_BIN="$SYSTEM_JAVA"

echo "Starting Minecraft 1.7.10..."
echo "Using Java: \$JAVA_BIN"
"\$JAVA_BIN" -Xmx${RAM_AMOUNT} -Xms1G -Dlog4j.configurationFile=log4j2_17-111.xml -jar server.jar nogui
EOF

chmod +x "$START_SCRIPT"
chown "$MC_USER":"$MC_USER" "$START_SCRIPT"

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "To start the server:"
echo -e "${YELLOW}sudo -u $MC_USER $START_SCRIPT${NC}"
echo -e "${GREEN}==========================================${NC}"