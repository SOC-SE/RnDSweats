#!/bin/bash
#
# LMD & ClamAV Scheduled Scan Setup Script
#
# This script automates the installation of ClamAV (scanner only) and LMD,
# and configures a cron job for periodic scanning every 15 minutes.
#
# It performs the following steps:
# 1. Checks for root privileges.
# 2. Detects the Linux distribution (Debian/RHEL based).
# 3. Defines a static list of high-risk directories to scan.
# 4. Installs LMD dependencies, ClamAV base tools, and freshclam.
#    (Does NOT install or run the resource-intensive clamav-daemon).
# 5. Downloads and installs the latest version of LMD.
# 6. Configures LMD to use the ClamAV engine (clamscan) and enables quarantine.
# 7. Creates a cron job to scan the specified paths every 15 minutes.
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
    FRESHCLAM_SERVICE="clamav-freshclam"
    # Note: clamav-daemon is intentionally removed
    INSTALL_PACKAGES="clamav clamav-freshclam inotify-tools"
    echo -e "${GREEN}Debian-based system detected.${NC}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    else
        PACKAGE_MANAGER="yum"
    fi
    FRESHCLAM_SERVICE="clamav-freshclam"
    EPEL_PACKAGE="epel-release"
    # Note: clamav-server (which provides clamd) is intentionally removed
    INSTALL_PACKAGES="clamav clamav-update inotify-tools"
    echo -e "${GREEN}Red Hat-based system detected.${NC}"
else
    echo -e "${RED}Unsupported Linux distribution. This script supports Debian/Ubuntu and RHEL/CentOS/Fedora.${NC}"
    exit 1
fi


# --- Directory Configuration ---

# 3. Define directories for scheduled scanning
echo -e "${YELLOW}Defining directories for scheduled scanning...${NC}"
# List of directories you specified
SCAN_LIST_ARRAY=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/home" "/etc/systemd/system" "/lib/systemd/system" "/root" "/var/fcgi_ipc")

FINAL_SCAN_PATHS_ARRAY=()
MISSING_PATHS=()

# Check that the specified directories exist before adding them to the list
for path in "${SCAN_LIST_ARRAY[@]}"; do
    if [ -d "$path" ]; then
        FINAL_SCAN_PATHS_ARRAY+=("$path")
    else
        MISSING_PATHS+=("$path")
    fi
done

# Create the final comma-separated string for maldet -a flag
SCAN_PATH_STRING=$(IFS=,; echo "${FINAL_SCAN_PATHS_ARRAY[*]}")

if [ -z "$SCAN_PATH_STRING" ]; then
    echo -e "${RED}Error: No valid directories found to scan from the predefined list. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}The following paths will be scanned periodically:${NC}"
# Use printf for a more reliable multi-line list
echo "${YELLOW}"
printf "  %s\n" "${FINAL_SCAN_PATHS_ARRAY[@]}"
echo "${NC}"

# Inform the user if any requested directories were skipped
if [ ${#MISSING_PATHS[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Note: The following paths were not found and will be skipped:${NC}"
    for path in "${MISSING_PATHS[@]}"; do
        echo -e "${YELLOW}- $path${NC}"
    done
fi


# --- Installation & Configuration ---

# 4. Install ClamAV (base tools only) and Dependencies
echo -e "\n${YELLOW}--- Installing ClamAV (base tools) and Dependencies ---${NC}"

if [ "$DISTRO" == "redhat" ]; then
    echo "Installing EPEL repository..."
    $PACKAGE_MANAGER install -y $EPEL_PACKAGE

    echo "Updating package lists..."
    $PACKAGE_MANAGER update -y

    echo "Installing packages: $INSTALL_PACKAGES"
    $PACKAGE_MANAGER install -y $INSTALL_PACKAGES

    # --- RHEL-based Service Configuration ---
    # Apply Ubuntu 18 config fix logic to RHEL freshclam.conf
    sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true

    echo "Stopping $FRESHCLAM_SERVICE to run manual update..."
    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true

    echo -e "${YELLOW}Downloading latest ClamAV virus definitions...${NC}"
    freshclam || echo -e "${YELLOW}Warning: freshclam update failed (likely due to rate limiting). Continuing...${NC}"

    echo "Enabling and starting ClamAV update service ($FRESHCLAM_SERVICE)..."
    systemctl enable --now "$FRESHCLAM_SERVICE"

elif [ "$DISTRO" == "debian" ]; then
    echo "Updating package lists..."
    $PACKAGE_MANAGER update -y

    echo "Installing packages: $INSTALL_PACKAGES"
    $PACKAGE_MANAGER install -y $INSTALL_PACKAGES

    # --- Debian-based Service Configuration ---
    # Apply config fixes for freshclam only
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true

    echo "Stopping $FRESHCLAM_SERVICE to run manual update..."
    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true

    echo -e "${YELLOW}Downloading latest ClamAV virus definitions...${NC}"
    freshclam || echo -e "${YELLOW}Warning: freshclam update failed (likely due to rate limiting). Continuing...${NC}"

    echo "Enabling and starting ClamAV update service ($FRESHCLAM_SERVICE)..."
    systemctl enable --now "$FRESHCLAM_SERVICE"
fi

echo -e "${GREEN}ClamAV installation and update service setup complete.${NC}"


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
# Redirect stdout and stderr during install to keep output clean
./install.sh > /dev/null 2>&1
echo -e "${GREEN}LMD installation complete.${NC}"


# 6. Configure LMD for Scheduled Scanning
echo -e "\n${YELLOW}--- Configuring LMD for Scheduled Scanning ---${NC}"
CONFIG_FILE="/usr/local/maldetect/conf.maldet"

# Use sed to modify the configuration file
sed -i 's/^email_alert = .*/email_alert = "0"/' "$CONFIG_FILE"
sed -i 's/^quarantine_hits = "0"/quarantine_hits = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_clamscan = "0"/scan_clamscan = "1"/' "$CONFIG_FILE"
sed -i 's/^scan_ignore_root = "1"/scan_ignore_root = "0"/' "$CONFIG_FILE"

# Comment out the clamd socket path as we are not using the daemon
sed -i 's~^scan_clamd_socket = "/var/run/clamav/clamd.sock"~#scan_clamd_socket = "/var/run/clamav/clamd.sock"~' "$CONFIG_FILE"


echo "LMD configuration updated:"
echo "- Email alerts disabled."
echo "- Automatic quarantine of malware hits enabled."
echo "- Integration with ClamAV scan engine (clamscan) enabled."
echo "- Scanning of root-owned files enabled."


# 7. Update LMD Signatures
echo -e "\n${YELLOW}--- Updating LMD Signatures ---${NC}"
echo "Updating LMD signatures..."
maldet -u > /dev/null 2>&1

echo "Checking for new LMD version..."
maldet -d > /dev/null 2>&1


# 8. Create Cron Job for Scheduled Scanning
echo -e "\n${YELLOW}--- Creating 15-Minute Scan Cron Job ---${NC}"
CRON_FILE="/etc/cron.d/maldet_scheduled_scan"

# Create the cron job file
echo "# This cron job runs a maldet scan every 15 minutes on high-risk directories." > "$CRON_FILE"
# Use the comma-separated path string with the -a flag
# The -b flag runs the scan in the background
echo "*/15 * * * * root /usr/local/sbin/maldet -b -a ${SCAN_PATH_STRING} > /dev/null 2>&1" >> "$CRON_FILE"

chmod 0644 "$CRON_FILE"
echo -e "${GREEN}Cron job created at ${CRON_FILE}${NC}"


echo -e "\n${GREEN}--- Setup Complete! ---${NC}"
echo -e "LMD and ClamAV are installed. LMD will now scan the following paths every 15 minutes via cron:"
# Use printf for a more reliable multi-line list
echo "${YELLOW}"
printf "  %s\n" "${FINAL_SCAN_PATHS_ARRAY[@]}"
echo "${NC}"
echo -e "\nDetected malware will be automatically quarantined."
echo -e "You can view the event log with the command:"
echo -e "${YELLOW}cat /usr/local/maldetect/logs/event_log${NC}"
echo -e "Scan reports can be found in: ${YELLOW}/usr/local/maldetect/sess/${NC}"

