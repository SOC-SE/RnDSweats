#!/bin/bash
#
# My finals are two weeks long this year. I'm about half way in and 3.5 all nighters deep. I take schedule 2.3 hour naps.
# I'm losing my sanity and we compete TOMORROW. So, here's me regaining some of it back.
#
# This script installs a bloody Minecraft server. No, really, it does. It *should* work on RHEL and Debian based 
# machines, but don't look at me if it fails. I'm tired boss.
#
#
# Samuel Brucker 2025-2026
#
#
#


ADMIN_UUID="3c8f12eb-31cd-4661-a9d9-2d4e4bb91919"

# Check for local Log4j file first
if [ ! -f "log4j2_17-111.xml" ]; then
    echo "Error: log4j2_17-111.xml not found in the current directory."
    echo "Please download it and place it next to this script."
    exit 1
fi

# Ask the user which version they want because apparently choice is important
echo "Which version of Minecraft do you want to install?"
echo "1) 1.7.10 (The classic)"
echo "2) 1.8.8 (UHC Ready)"
read -r -p "Select an option [1-2]: " VERSION_CHOICE

case $VERSION_CHOICE in
    1)
        MC_VERSION="1.7.10"
        SOURCE_JAR="server_1.7.10.jar"
        INSTALL_DIR="/opt/mc_server_1.7.10"
        ;;
    2)
        MC_VERSION="1.8.8"
        SOURCE_JAR="server_1.8.8.jar"
        INSTALL_DIR="/opt/mc_server_1.8.8"
        ;;
    *)
        echo "You didn't type 1 or 2. I'm too tired to argue. Defaulting to 1.8.8."
        MC_VERSION="1.8.8"
        SOURCE_JAR="server_1.8.8.jar"
        INSTALL_DIR="/opt/mc_server_1.8.8"
        ;;
esac

# Check local JAR existence
if [ ! -f "$SOURCE_JAR" ]; then
    echo -e "\033[0;31mError: $SOURCE_JAR not found in the current directory.\033[0m"
    echo "Please ensure the server jar is named exactly '$SOURCE_JAR' and is in this folder."
    exit 1
fi

# Ask for OP user
echo ""
echo "Do you want to automatically OP yourself on startup? (y/n)"
read -r -p "Choice: " WANT_OP
OP_USERNAME=""
if [[ "$WANT_OP" =~ ^[Yy]$ ]]; then
    if [ "$ADMIN_UUID" == "REPLACE_THIS_WITH_YOUR_FULL_UUID" ]; then
        echo -e "\033[0;31mWARNING: You didn't edit the script to add your UUID! OP will fail.\033[0m"
        echo "Please edit line 16 of this script and run it again."
        exit 1
    fi
    read -r -p "Enter your Minecraft Username: " OP_USERNAME
fi

MC_USER="mcadmin"
RAM_AMOUNT="3G"
SERVICE_NAME="mc-server"

#pretty colours <3
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Starting Minecraft $MC_VERSION Server Installer...${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}run this script as root u noob${NC}"
  exit 1
fi


if command -v apt > /dev/null; then
    echo "trying to get packages for my special little apt minecrafter"
    apt-get update
    # Attempt to install essentials first
    echo "Installing Java/Wget/Curl..."
    if apt-cache show openjdk-8-jre-headless > /dev/null 2>&1; then
        apt-get install -y openjdk-8-jre-headless wget curl
    else
        echo -e "${YELLOW}OpenJDK 8 not found. Installing default-jre.${NC}"
        apt-get install -y default-jre wget curl
    fi

elif command -v dnf > /dev/null; then
    echo "trying to get packages for my special little dnf minecrafter"
    dnf clean all
    # Install Essentials FIRST
    echo "Installing Java/Wget/Curl..."
    dnf install -y java-1.8.0-openjdk-headless wget curl

elif command -v yum > /dev/null; then
    echo "trying to get packages for my special little yum minecrafter"
    # Install Essentials FIRST
    yum install -y java-1.8.0-openjdk-headless wget curl

else
    echo -e "${RED}Error: No supported package manager found (apt, dnf, yum).${NC}"
    exit 1
fi

echo -e "${YELLOW}Verifying installation...${NC}"

if ! command -v wget > /dev/null; then
    echo -e "${RED}wget failed to install, wtf did you do to this box????${NC}"
    exit 1
fi

# Java Detection Logic - Robust
if [ -f "/usr/lib/jvm/jre-1.8.0-openjdk/bin/java" ]; then
    echo "Found Java at /usr/lib/jvm/jre-1.8.0-openjdk/bin/java"
    SYSTEM_JAVA="/usr/lib/jvm/jre-1.8.0-openjdk/bin/java"
elif [ -f "/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java" ]; then
    echo "Found Java at /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
    SYSTEM_JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
elif command -v java > /dev/null 2>&1; then
    # Dynamically find the path if hardcoded ones fail
    SYSTEM_JAVA=$(command -v java)
    echo "Found Java via command at: $SYSTEM_JAVA"
else
    echo -e "${RED}CRITICAL ERROR: Java 8 could not be found anywhere. Installation aborted.${NC}"
    exit 1
fi

echo -e "${YELLOW}Setting up '$MC_USER' user so we don't get fucked and directory at: $INSTALL_DIR${NC}"

if ! id "$MC_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$MC_USER"
fi

mkdir -p "$INSTALL_DIR"
chown -R "$MC_USER":"$MC_USER" "$INSTALL_DIR"

# Handle OP file creation (JSON Format)
if [ ! -z "$OP_USERNAME" ]; then
    echo -e "${YELLOW}Creating ops.json for $OP_USERNAME...${NC}"
    cat <<EOF > "$INSTALL_DIR/ops.json"
[
  {
    "uuid": "$ADMIN_UUID",
    "name": "$OP_USERNAME",
    "level": 4
  }
]
EOF
    chown "$MC_USER":"$MC_USER" "$INSTALL_DIR/ops.json"
fi

# Copy the local Log4j file
echo -e "${YELLOW}Copying local Log4j fix...${NC}"
cp "log4j2_17-111.xml" "$INSTALL_DIR/log4j2_17-111.xml"

# CHECK IF LOG4J FILE IS EMPTY (Fixes the Fatal Error :1:1 issue)
if [ ! -s "$INSTALL_DIR/log4j2_17-111.xml" ]; then
    echo -e "${RED}Warning: Local log4j2_17-111.xml was empty or corrupt.${NC}"
    echo -e "${YELLOW}Generating a safe fallback Log4j config...${NC}"
    cat <<EOF > "$INSTALL_DIR/log4j2_17-111.xml"
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="SysOut" target="SYSTEM_OUT">
            <PatternLayout pattern="[%d{HH:mm:ss}] [%t/%level]: %msg%n" />
        </Console>
    </Appenders>
    <Loggers>
        <Root level="info">
            <AppenderRef ref="SysOut" />
        </Root>
    </Loggers>
</Configuration>
EOF
fi
chown "$MC_USER":"$MC_USER" "$INSTALL_DIR/log4j2_17-111.xml"

# Copy Server JAR locally
echo -e "${YELLOW}Copying local server JAR ($SOURCE_JAR)...${NC}"
cp "$SOURCE_JAR" "$INSTALL_DIR/server.jar"
chown "$MC_USER":"$MC_USER" "$INSTALL_DIR/server.jar"

cd "$INSTALL_DIR" || exit

if [ ! -f server.jar ]; then
    echo -e "${RED}Error: Server JAR copy failed. FML.${NC}"
    exit 1
fi

echo "eula=true" | sudo -u "$MC_USER" tee eula.txt > /dev/null

START_SCRIPT="$INSTALL_DIR/start.sh"
echo -e "${YELLOW}Creating start script wrapper...${NC}"

cat <<EOF > "$START_SCRIPT"
#!/bin/bash
cd "$INSTALL_DIR"
JAVA_BIN="$SYSTEM_JAVA"
echo "Starting Minecraft $MC_VERSION..."
# exec replaced the shell process with java, ensuring signals (like stop) go straight to the server
exec "\$JAVA_BIN" -Xmx${RAM_AMOUNT} -Xms1G -Dlog4j.configurationFile=log4j2_17-111.xml -jar server.jar nogui
EOF

chmod +x "$START_SCRIPT"
chown "$MC_USER":"$MC_USER" "$START_SCRIPT"

# --- SYSTEMD SERVICE CREATION ---
echo -e "${YELLOW}Creating systemd service file...${NC}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Minecraft $MC_VERSION Server
After=network.target

[Service]
User=$MC_USER
Group=$MC_USER
WorkingDirectory=$INSTALL_DIR
# Run the start script directly. No screen.
ExecStart=$START_SCRIPT
Restart=on-failure
RestartSec=10
# Logs go directly to journalctl
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo -e "${YELLOW}Reloading systemd daemon...${NC}"
systemctl daemon-reload
# Disable old service names if they exist just in case
systemctl disable mc-1.7.10 2>/dev/null
systemctl disable mc-1.8.8 2>/dev/null

echo -e "It worked. Probably. If you want to actually enjoy life, here are your new commands:"
echo -e "Start server: ${YELLOW}systemctl start $SERVICE_NAME${NC}"
echo -e "Check logs:   ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
echo -e "Stop server:  ${YELLOW}systemctl stop $SERVICE_NAME${NC}"
echo -e "Enable on boot: ${YELLOW}systemctl enable $SERVICE_NAME${NC}"