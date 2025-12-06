#!/bin/bash
#
# My finals are two weeks long this year. I'm about half way in and 3.5 all nighters deep. I take scheduled 2.3 hour naps.
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

# Ask the user which version they want because apparently choice is important
echo "Which version of Minecraft do you want to install?"
echo "1) 1.7.10 (The classic)"
echo "2) 1.8.8 (UHC Ready)"
read -r -p "Select an option [1-2]: " VERSION_CHOICE

case $VERSION_CHOICE in
    1)
        MC_VERSION="1.7.10"
        SERVER_URL="https://launcher.mojang.com/v1/objects/952438ac4e01b4d115c5fc38f891710c4941df29/server.jar"
        INSTALL_DIR="/opt/mc_server_1.7.10"
        ;;
    2)
        MC_VERSION="1.8.8"
        SERVER_URL="https://launcher.mojang.com/v1/objects/5fafba3f58c40dc51b5c3ca72a98f62dfdae003c/server.jar"
        INSTALL_DIR="/opt/mc_server_1.8.8"
        ;;
    *)
        echo "You didn't type 1 or 2. I'm too tired to argue. Defaulting to 1.8.8."
        MC_VERSION="1.8.8"
        SERVER_URL="https://launcher.mojang.com/v1/objects/5fafba3f58c40dc51b5c3ca72a98f62dfdae003c/server.jar"
        INSTALL_DIR="/opt/mc_server_1.8.8"
        ;;
esac

# Ask for OP user
echo ""
echo "Do you want to automatically OP a player on startup? (y/n)"
read -r -p "Choice: " WANT_OP
OP_USERNAME=""
if [[ "$WANT_OP" =~ ^[Yy]$ ]]; then
    read -r -p "Enter the exact Minecraft Username to OP: " OP_USERNAME
fi

LOG4J_URL="https://launcher.mojang.com/v1/objects/4bb89a97a66f570bddc5592c671d46345a060f08/log4j2_17-111.xml"
MC_USER="mcadmin"
RAM_AMOUNT="2G"
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
    if apt-cache show openjdk-8-jre-headless > /dev/null 2>&1; then
        apt-get install -y openjdk-8-jre-headless wget screen curl
    else
        echo -e "${YELLOW}OpenJDK 8 not found. Installing default-jre (Warning: MC $MC_VERSION might not work with Java 17+).${NC}"
        apt-get install -y default-jre wget screen curl
    fi

elif command -v dnf > /dev/null; then
    echo "trying to get packages for my special little dnf minecrafter"
    dnf install -y epel-release
    dnf clean all
    dnf install -y java-1.8.0-openjdk-headless wget screen curl

elif command -v yum > /dev/null; then
    echo "trying to get packages for my special little yum minecrafter"
    yum install -y epel-release
    yum install -y java-1.8.0-openjdk-headless wget screen curl

else
    echo -e "${RED}Error: No supported package manager found (apt, dnf, yum).${NC}"
    exit 1
fi

echo -e "${YELLOW}Verifying installation...${NC}"

if ! command -v wget > /dev/null; then
    echo -e "${RED}wget failed to install, wtf did you do to this box????${NC}"
    exit 1
fi

if ! command -v screen > /dev/null; then
    echo -e "${RED}screen failed to install, wtf did you do to this box????${NC}"
    exit 1
fi

if ! command -v java > /dev/null; then
    echo -e "${RED}Error: 'java' command not found. Checking for specific binary paths... you dumbass${NC}"
    # Try to find java 8 specifically if 'java' alias isn't set
    if [ -f "/usr/lib/jvm/jre-1.8.0-openjdk/bin/java" ]; then
        echo "Found Java at /usr/lib/jvm/jre-1.8.0-openjdk/bin/java"
        SYSTEM_JAVA="/usr/lib/jvm/jre-1.8.0-openjdk/bin/java"
    elif [ -f "/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java" ]; then
        echo "Found Java at /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
        SYSTEM_JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
    else
        echo -e "${RED}CRITICAL ERROR: Java 8 could not be found. The script has decided you're not cool enough. \n\n\n\nBe sad about it.${NC}"
        exit 1
    fi
else
    SYSTEM_JAVA="java"
fi

echo -e "${YELLOW}Setting up '$MC_USER' user so we don't get fucked and directory at: $INSTALL_DIR${NC}"

if ! id "$MC_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$MC_USER"
fi

mkdir -p "$INSTALL_DIR"
chown -R "$MC_USER":"$MC_USER" "$INSTALL_DIR"

# Handle OP file creation
if [ ! -z "$OP_USERNAME" ]; then
    echo -e "${YELLOW}Creating ops.txt for $OP_USERNAME...${NC}"
    # Valid for both 1.7.10 and 1.8.8 - server converts this to ops.json on startup
    echo "$OP_USERNAME" > "$INSTALL_DIR/ops.txt"
    chown "$MC_USER":"$MC_USER" "$INSTALL_DIR/ops.txt"
fi

cd "$INSTALL_DIR" || exit
echo -e "${YELLOW}Downloading Server Files...${NC}"

sudo -u "$MC_USER" wget -O server.jar "$SERVER_URL"
# Switched to curl as requested
sudo -u "$MC_USER" curl -o log4j2_17-111.xml "$LOG4J_URL"

if [ ! -f server.jar ]; then
    echo -e "${RED}Error: Server JAR failed to download. FML.${NC}"
    exit 1
fi

echo "eula=true" | sudo -u "$MC_USER" tee eula.txt > /dev/null #everytime I see tee, I want to do teehee.... holy shit I should alias that

START_SCRIPT="$INSTALL_DIR/start.sh"
echo -e "${YELLOW}Creating start script wrapper...${NC}"

# We are switching to systemd, so we don't need screen inside the start script anymore.
# We REMOVE 'exec' to ensure the shell stays active, which helps with input piping in some screen versions.
cat <<EOF > "$START_SCRIPT"
#!/bin/bash
cd "$INSTALL_DIR"
JAVA_BIN="$SYSTEM_JAVA"
echo "Starting Minecraft $MC_VERSION..."
"\$JAVA_BIN" -Xmx${RAM_AMOUNT} -Xms1G -Dlog4j.configurationFile=log4j2_17-111.xml -jar server.jar nogui
EOF

chmod +x "$START_SCRIPT"
chown "$MC_USER":"$MC_USER" "$START_SCRIPT"

# --- SYSTEMD SERVICE CREATION ---
echo -e "${YELLOW}Creating systemd service file...${NC}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCREEN_BIN=$(command -v screen)

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Minecraft $MC_VERSION Server
After=network.target

[Service]
User=$MC_USER
Group=$MC_USER
WorkingDirectory=$INSTALL_DIR
# Force xterm environment so Java detects a terminal and accepts input
Environment=TERM=xterm

# We wrap the start script in screen -DmS. 
# -D ensures it stays in foreground (for systemd)
# -m ensures it creates a new session
# -S names it 'mc-console' so we can find it
# We explicitly call /bin/bash to ensure the script runs in a shell inside screen
ExecStart=$SCREEN_BIN -DmS mc-console /bin/bash $START_SCRIPT

# Stop gracefully by injecting the 'stop' command into the console
ExecStop=$SCREEN_BIN -p 0 -S mc-console -X eval 'stuff "stop"\\015'

Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo -e "${YELLOW}Reloading systemd daemon...${NC}"
systemctl daemon-reload

systemctl enable --now $SERVICE_NAME

echo -e "It worked. Probably. If you want to actually enjoy life, here's info for you to administrate MC:"
echo -e "Service name: ${YELLOW}$SERVICE_NAME${NC}"
echo -e "Restart server when RT breaks it: ${YELLOW}systemctl restart $SERVICE_NAME${NC}"
echo -e "Access Console: ${YELLOW}sudo -u $MC_USER screen -r mc-console${NC}  (Ctrl+A, D to detach)"
echo -e "Check logs:   ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"