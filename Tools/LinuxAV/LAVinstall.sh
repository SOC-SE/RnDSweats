#!/bin/bash
#
# LMD & ClamAV Real-Time Monitor Setup Script
#
# This script automates the installation and configuration of ClamAV and
# Linux Malware Detect (LMD) for efficient, real-time file monitoring.
#
# It performs the following steps:
# 1. Checks for root privileges.
# 2. Detects the Linux distribution (Debian/RHEL based).
# 3. Prompts for a directory path to monitor.
# 4. Installs and configures ClamAV, including the daemon for performance.
# 5. Downloads and installs the latest version of LMD.
# 6. Configures LMD to use the ClamAV engine and enables quarantine.
# 7. Starts LMD's real-time monitoring service on the specified path.
#
#  Samuel Brucker 2025-2026
#
#

# --- Script Configuration & Colors ---
set -e # Exit immediately if a command exits with a non-zero status.

# Colors for better output readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Pre-flight Checks ---

# 1. Check for root privileges
if [ "$(id -u)" -ne "0" ]; then
   echo -e "${RED}This script must be run as root. Please use sudo or log in as the root user.${NC}"
   exit 1
fi

# 2. Detect Linux Distribution
echo -e "${YELLOW}Detecting Linux distribution...${NC}"
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
    PACKAGE_MANAGER="apt-get"
    CLAMAV_PACKAGES="clamav clamav-daemon"
    CLAMAV_DAEMON_SERVICE="clamav-daemon"
    echo -e "${GREEN}Debian-based system detected.${NC}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    else
        PACKAGE_MANAGER="yum"
    fi
    # EPEL (Extra Packages for Enterprise Linux) is required for ClamAV
    EPEL_PACKAGE="epel-release"
    CLAMAV_PACKAGES="clamav-server clamav-data clamav-update"
    CLAMAV_DAEMON_SERVICE="clamd@scan" # Service name for modern RHEL/CentOS
    echo -e "${GREEN}Red Hat-based system detected.${NC}"
else
    echo -e "${RED}Unsupported Linux distribution. This script supports Debian/Ubuntu and RHEL/CentOS/Fedora.${NC}"
    exit 1
fi


# --- User Input ---

# 3. Prompt for the directory to monitor
read -p "Please enter the full path of the directory to monitor (e.g., /var/www or /home): " MONITOR_PATH

if [ ! -d "$MONITOR_PATH" ]; then
    echo -e "${RED}Error: The directory '$MONITOR_PATH' does not exist.${NC}"
    exit 1
fi
echo -e "${GREEN}The directory '$MONITOR_PATH' will be monitored.${NC}"


# --- Installation & Configuration ---

# 4. Install ClamAV and its daemon
echo -e "\n${YELLOW}--- Installing and Configuring ClamAV ---${NC}"
if [ "$DISTRO" == "redhat" ]; then
    echo "Installing EPEL repository..."
    $PACKAGE_MANAGER install -y $EPEL_PACKAGE
fi

echo "Updating package lists..."
$PACKAGE_MANAGER update -y

echo "Installing ClamAV packages: $CLAMAV_PACKAGES"
$PACKAGE_MANAGER install -y $CLAMAV_PACKAGES

echo "Stopping ClamAV services to download definitions..."
# Stop services to avoid conflicts during initial definition download
systemctl stop "$CLAMAV_DAEMON_SERVICE" 2>/dev/null || true
systemctl stop clamav-freshclam 2>/dev/null || true


echo -e "${YELLOW}Downloading latest ClamAV virus definitions... (This may take several minutes)${NC}"
freshclam

echo "Enabling and starting the ClamAV daemon for high-performance scanning..."
# The daemon keeps definitions in memory, preventing massive resource spikes
systemctl enable "$CLAMAV_DAEMON_SERVICE"
systemctl start "$CLAMAV_DAEMON_SERVICE"
echo -e "${GREEN}ClamAV installation and daemon setup complete.${NC}"


# 5. Install Linux Malware Detect (LMD)
echo -e "\n${YELLOW}--- Installing Linux Malware Detect (LMD) ---${NC}"
cd /tmp
if [ -f "maldetect-current.tar.gz" ]; then
    rm -f maldetect-current.tar.gz
fi
if [ -d maldetect-* ]; then
    rm -rf maldetect-*/
fi

echo "Downloading the latest version of LMD..."
wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xzf maldetect-current.tar.gz

# Find the extracted directory name
LMD_DIR=$(find . -maxdepth 1 -type d -name "maldetect-*")

if [ -z "$LMD_DIR" ]; then
    echo -e "${RED}Failed to find the LMD installation directory after extraction.${NC}"
    exit 1
fi

cd "$LMD_DIR"
echo "Running the LMD installer..."
./install.sh > /dev/null 2>/dev/null
echo -e "${GREEN}LMD installation complete.${NC}"


# 6. Configure LMD for Real-Time Monitoring
echo -e "\n${YELLOW}--- Configuring LMD for Real-Time Monitoring ---${NC}"
CONFIG_FILE="/usr/local/maldetect/conf.maldet"

# Use sed to modify the configuration file
sed -i 's/^email_alert = "0"/email_alert = "1"/' "$CONFIG_FILE"
sed -i 's/^email_addr = "you@domain.com"/email_addr = "root@localhost"/' "$CONFIG_FILE"
sed -i 's/^quarantine_hits = "0"/quarantine_hits = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_clamscan = "0"/scan_clamscan = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_ignore_root = "1"/scan_ignore_root = "0"/' "$CONFIG_EXAMPLE"

echo "LMD configuration updated:"
echo "- Email alerts enabled (sent to root@localhost)"
echo "- Automatic quarantine of malware hits enabled."
echo "- Integration with ClamAV scan engine enabled."
echo "- Scanning of root-owned files enabled."


# 7. Start Real-Time Monitoring
echo -e "\n${YELLOW}--- Starting Real-Time Monitoring ---${NC}"
echo "Updating LMD signatures..."
maldet -u > /dev/null 2>&1

echo "Checking for new LMD version..."
maldet -d > /dev/null 2>&1

echo "Starting real-time monitoring on '$MONITOR_PATH'..."
# This command starts the inotify monitor process in the background
maldet --monitor "$MONITOR_PATH"

echo -e "\n${GREEN}--- Setup Complete! ---${NC}"
echo -e "LMD is now actively monitoring ${YELLOW}${MONITOR_PATH}${NC} for file changes."
echo -e "Detected malware will be automatically quarantined."
echo -e "You can view the real-time event log with the command:"
echo -e "${YELLOW}tail -f /usr/local/maldetect/logs/event_log${NC}"
echo -e "Scan reports can be found in: ${YELLOW}/usr/local/maldetect/sess/${NC}"

