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
# 3. Defines a static list of high-risk directories to monitor.
# 4. Installs LMD dependencies, then downloads and installs ClamAV
#    from the official .deb/.rpm binaries.
# 5. Downloads and installs the latest version of LMD.
# 6. Configures LMD to use the ClamAV engine and enables quarantine.
# 7. Starts LMD's real-time monitoring service on the specified paths.
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
    echo -e "${GREEN}Debian-based system detected.${NC}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    else
        PACKAGE_MANAGER="yum"
    fi
    echo -e "${GREEN}Red Hat-based system detected.${NC}"
else
    echo -e "${RED}Unsupported Linux distribution. This script supports Debian/Ubuntu and RHEL/CentOS/Fedora.${NC}"
    exit 1
fi


# --- Directory Configuration ---

# 3. Define directories for real-time monitoring
echo -e "${YELLOW}Defining directories for real-time monitoring...${NC}"
# List of directories you specified
MONITOR_LIST_ARRAY=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/home" "/etc/systemd/system" "/lib/systemd/system" "/root")

FINAL_MONITOR_PATHS_ARRAY=()
MISSING_PATHS=()

# Check that the specified directories exist before adding them to the list
for path in "${MONITOR_LIST_ARRAY[@]}"; do
    if [ -d "$path" ]; then
        FINAL_MONITOR_PATHS_ARRAY+=("$path")
    else
        MISSING_PATHS+=("$path")
    fi
done

# Create the final comma-separated string for maldet
MONITOR_PATH=$(IFS=,; echo "${FINAL_MONITOR_PATHS_ARRAY[*]}")

if [ -z "$MONITOR_PATH" ]; then
    echo -e "${RED}Error: No valid directories found to monitor from the predefined list. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}The following paths will be monitored:${NC}"
# Print as a multi-line list for clarity
echo -e "${YELLOW}${MONITOR_PATH//,/\n}${NC}"

# Inform the user if any requested directories were skipped
if [ ${#MISSING_PATHS[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Note: The following paths were not found and will be skipped:${NC}"
    for path in "${MISSING_PATHS[@]}"; do
        echo -e "${YELLOW}- $path${NC}"
    done
fi


# --- Installation & Configuration ---

# 4. Install ClamAV and its daemon (from Official Binaries)
echo -e "\n${YELLOW}--- Installing and Configuring ClamAV (from Official Binary) ---${NC}"

# Installer URLs
DEB_URL="https://www.clamav.net/downloads/production/clamav-1.5.1.linux.x86_64.deb"
RPM_URL="https://www.clamav.net/downloads/production/clamav-1.5.1.linux.x86_64.rpm"

# These new installers use standardized service names
FRESHCLAM_SERVICE="clamav-freshclam"
CLAMAV_DAEMON_SERVICE="clamav-clamd"

cd /tmp

if [ "$DISTRO" == "redhat" ]; then
    echo "Installing LMD dependencies (inotify-tools) and wget..."
    $PACKAGE_MANAGER install -y inotify-tools wget
    
    echo "Downloading official ClamAV RPM..."
    wget -q -O clamav.rpm "$RPM_URL"
    
    echo "Installing ClamAV from RPM... (This will also pull dependencies)"
    # dnf/yum can install local RPMs and resolve repo dependencies
    $PACKAGE_MANAGER install -y ./clamav.rpm
    rm -f ./clamav.rpm

elif [ "$DISTRO" == "debian" ]; then
    echo "Updating package lists..."
    $PACKAGE_MANAGER update -y
    
    echo "Installing LMD dependencies (inotify-tools) and wget..."
    # 'wget' is needed to download, 'inotify-tools' is for LMD's monitor
    $PACKAGE_MANAGER install -y inotify-tools wget
    
    echo "Downloading official ClamAV DEB..."
    wget -q -O clamav.deb "$DEB_URL"
    
    echo "Installing ClamAV from DEB..."
    dpkg -i ./clamav.deb || true # Install, ignore errors for now
    
    echo "Fixing any missing dependencies..."
    # This is the critical step after dpkg to pull in dependencies
    $PACKAGE_MANAGER -f install -y
    rm -f ./clamav.deb
fi

echo "Stopping ClamAV services to download definitions..."
# Stop services to avoid conflicts during initial definition download
systemctl stop "$CLAMAV_DAEMON_SERVICE" 2>/dev/null || true
systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true


echo -e "${YELLOW}Downloading latest ClamAV virus definitions... (This may take several minutes)${NC}"
# The freshclam binary will be in the path after the install
# We add '|| true' to this command. If freshclam fails (e.g., due to a 429 rate limit),
# this will prevent 'set -e' from exiting the script.
freshclam || echo -e "${YELLOW}Warning: freshclam update failed (likely due to rate limiting). Continuing installation...${NC}"

echo "Enabling and starting the ClamAV daemon for high-performance scanning..."
# The daemon keeps definitions in memory, preventing massive resource spikes
systemctl enable "$CLAMAV_DAEMON_SERVICE"
systemctl start "$CLAMAV_DAEMON_SERVICE"

echo "Enabling and starting the ClamAV definition update service..."
# Re-enable and start the freshclam service so definitions stay up-to-date
systemctl enable "$FRESHCLAM_SERVICE"
systemctl start "$FRESHCLAM_SERVICE"

# Give the services a moment to start and create the socket
echo "Waiting 5 seconds for services to initialize..."
sleep 5

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
sed -i 's/^email_alert = .*/email_alert = "0"/' "$CONFIG_FILE"
# email_addr line is not needed since alerts are off
sed -i 's/^quarantine_hits = "0"/quarantine_hits = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_clamscan = "0"/scan_clamscan = "1"/' "$CONFIG_FILE"
# This setting is required to scan root-owned paths like /root and /etc
sed -i 's/^scan_ignore_root = "1"/scan_ignore_root = "0"/' "$CONFIG_FILE"

# --- NEW FIX ---
# Tell LMD where to find the clamd socket, as the new binary may
# place it in a non-standard location that LMD doesn't auto-detect.
# /var/run/clamav/clamd.sock is the most common default.
sed -i 's~^#scan_clamd_socket = ""~scan_clamd_socket = "/var/run/clamav/clamd.sock"~' "$CONFIG_FILE"

echo "LMD configuration updated:"
echo "- Email alerts disabled."
echo "- Automatic quarantine of malware hits enabled."
echo "- Integration with ClamAV scan engine enabled."
echo "- Scanning of root-owned files enabled."
echo "- Explicitly set clamd socket path for reliability."


# 7. Start Real-Time Monitoring
echo -e "\n${YELLOW}--- Starting Real-Time Monitoring ---${NC}"
echo "Updating LMD signatures..."
maldet -u > /dev/null 2>&1

echo "Checking for new LMD version..."
maldet -d > /dev/null 2>&1

echo "Starting real-time monitoring on all configured paths..."
# This command starts the inotify monitor process in the background
maldet --monitor "$MONITOR_PATH"

echo -e "\n${GREEN}--- Setup Complete! ---${NC}"
echo -e "LMD is now actively monitoring for file changes in:"
# Use printf for a more reliable multi-line list
echo "${YELLOW}"
printf "  %s\n" "${FINAL_MONITOR_PATHS_ARRAY[@]}"
echo "${NC}"
echo -e "\nYou can view the real-time event log with the command:"
echo -e "${YELLOW}tail -f /usr/local/maldetect/logs/event_log${NC}"
echo -e "Scan reports can be found in: ${YELLOW}/usr/local/maldetect/sess/${NC}"

