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
# 4. Installs LMD dependencies and ClamAV from the system's package manager
#    using the user-verified installation and service start order.
# 5. Downloads and installs the latest version of LMD.
# 6. Configures LMD to use the ClamAV engine and enables quarantine.
# 7. Starts LMD's real-time monitoring service on the specified paths.
#
#  Samuel Brucker 2025-2026
#
#

# --- Script Configuration & Colors ---
set -euo pipefail # Exit on error, unset variable, or pipe failure

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
    # Service names for Ubuntu/Debian packages
    FRESHCLAM_SERVICE="clamav-freshclam"
    CLAMAV_DAEMON_SERVICE="clamav-daemon"
    CLAMAV_PACKAGES="clamav clamav-daemon inotify-tools"
    echo -e "${GREEN}Debian-based system detected.${NC}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    else
        PACKAGE_MANAGER="yum"
    fi
    # Service name for modern RHEL/CentOS
    FRESHCLAM_SERVICE="clamav-freshclam"
    CLAMAV_DAEMON_SERVICE="clamd@scan"
    EPEL_PACKAGE="epel-release"
    CLAMAV_PACKAGES="clamav-server clamav-data clamav-update inotify-tools"
    echo -e "${GREEN}Red Hat-based system detected.${NC}"
else
    echo -e "${RED}Unsupported Linux distribution. This script supports Debian/Ubuntu and RHEL/CentOS/Fedora.${NC}"
    exit 1
fi


# --- Directory Configuration ---

# 3. Define directories for real-time monitoring
echo -e "${YELLOW}Defining directories for real-time monitoring...${NC}"
# List of directories you specified
MONITOR_LIST_ARRAY=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/home" "/etc/systemd/system" "/lib/systemd/system" "/root" "/var/fcgi_ipc")

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
# Use printf for a more reliable multi-line list
echo "${YELLOW}"
printf "  %s\n" "${FINAL_MONITOR_PATHS_ARRAY[@]}"
echo "${NC}"

# Inform the user if any requested directories were skipped
if [ ${#MISSING_PATHS[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Note: The following paths were not found and will be skipped:${NC}"
    for path in "${MISSING_PATHS[@]}"; do
        echo -e "${YELLOW}- $path${NC}"
    done
fi


# --- Installation & Configuration ---

# 4. Install ClamAV and its daemon (from Package Manager)
echo -e "\n${YELLOW}--- Installing and Configuring ClamAV (from Package Manager) ---${NC}"

if [ "$DISTRO" == "redhat" ]; then
    echo "Installing EPEL repository..."
    $PACKAGE_MANAGER install -y $EPEL_PACKAGE
    
    echo "Updating package lists..."
    $PACKAGE_MANAGER update -y
    
    echo "Installing ClamAV & LMD dependencies: $CLAMAV_PACKAGES"
    $PACKAGE_MANAGER install -y $CLAMAV_PACKAGES
    
    # --- RHEL-based Service Configuration ---
    # Apply Ubuntu 18 config fix logic to RHEL-based systems
    # This ensures the config is valid before starting services
    sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf 2>/dev/null || true
    sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true

    echo "Stopping $FRESHCLAM_SERVICE to run manual update..."
    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true
    
    echo -e "${YELLOW}Downloading latest ClamAV virus definitions...${NC}"
    freshclam || echo -e "${YELLOW}Warning: freshclam update failed (likely due to rate limiting). Continuing...${NC}"
    
    echo "Enabling and starting ClamAV services..."
    systemctl enable --now "$FRESHCLAM_SERVICE"
    systemctl enable --now "$CLAMAV_DAEMON_SERVICE"

elif [ "$DISTRO" == "debian" ]; then
    echo "Updating package lists..."
    $PACKAGE_MANAGER update -y
    
    echo "Installing ClamAV & LMD dependencies: $CLAMAV_PACKAGES"
    $PACKAGE_MANAGER install -y $CLAMAV_PACKAGES

    # --- Debian-based Service Configuration (Your tested procedure) ---
    echo "Applying configuration fixes for Debian-based system (Ubuntu 18)..."
    sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf 2>/dev/null || true
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true
    sed -i 's~^#LocalSocket /var/run/clamav/clamd.sock~LocalSocket /var/run/clamav/clamd.sock~' /etc/clamav/clamd.conf 2>/dev/null || true

    echo "Stopping $FRESHCLAM_SERVICE to run manual update..."
    systemctl stop "$FRESHCLAM_SERVICE" 2>/dev/null || true

    echo -e "${YELLOW}Downloading latest ClamAV virus definitions...${NC}"
    freshclam || echo -e "${YELLOW}Warning: freshclam update failed (likely due to rate limiting). Continuing...${NC}"

    echo "Enabling and starting ClamAV services..."
    systemctl enable --now "$FRESHCLAM_SERVICE"
    systemctl enable --now "$CLAMAV_DAEMON_SERVICE"
fi

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
# Clean up any existing maldetect directories
for dir in maldetect-*/; do
    [ -d "$dir" ] && rm -rf "$dir"
done

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

# Tell LMD where to find the clamd socket.
# /var/run/clamav/clamd.sock is the default for the Ubuntu package.
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

