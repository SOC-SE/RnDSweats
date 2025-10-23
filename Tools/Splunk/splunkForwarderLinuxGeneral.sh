#!/bin/bash
# Automates the installation of the Splunk Universal Forwarder. Currently set to v9.1.1, but that is easily changed.
# Works with Debian, Ubuntu, CentOS, Fedora, and Oracle Linux. You need to run this as sudo.

# This was put together as an amalgamation of code from my own work, other automatic installation scripts, and AI to tie everything together.
# Lots time went into this script. Be nice to it plz <3
#
# Samuel Brucker 2024-2025

# Define Splunk Forwarder variables
SPLUNK_VERSION="10.0.1"
SPLUNK_BUILD="c486717c322b"
SPLUNK_PACKAGE_TGZ="splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.tgz"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PACKAGE_TGZ}"
INSTALL_DIR="/opt/splunkforwarder"


# Set defaults for configuration
DEFAULT_INDEXER_IP="172.20.241.20"
DEFAULT_ADMIN_USERNAME="admin"
DEFAULT_ADMIN_PASSWORD="Changeme1!"  # Replace with a secure password

# Override defaults with command-line arguments if they are provided
# Usage: ./script.sh [indexer_ip] [username] [password]
INDEXER_IP=${1:-$DEFAULT_INDEXER_IP}
ADMIN_USERNAME=${2:-$DEFAULT_ADMIN_USERNAME}
ADMIN_PASSWORD=${3:-$DEFAULT_ADMIN_PASSWORD}

# Pretty colors :)
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'  #No Color - resets the color back to default

# Function to check for required command dependencies
check_dependencies() {
  local missing_deps=()
  for cmd in wget tar setfacl; do
    if ! command -v "$cmd" &> /dev/null; then
      missing_deps+=("$cmd")
    fi
  done

  if [ ${#missing_deps[@]} -gt 0 ]; then
    echo "${RED}Error: Missing required dependencies: ${missing_deps[*]}.${NC}"
    echo "${YELLOW}Please install them and run the script again.${NC}"
    exit 1
  fi
}

# --- SCRIPT EXECUTION STARTS HERE ---
check_dependencies

# Announce the configuration that will be used
echo "${BLUE}--- Splunk Forwarder Configuration ---${NC}"
echo "${GREEN}Indexer IP:      ${NC}$INDEXER_IP"
echo "${GREEN}Admin Username:  ${NC}$ADMIN_USERNAME"
echo "${GREEN}Admin Password:  ${NC}(hidden)"
echo "${BLUE}------------------------------------${NC}"

# Make sure this is being run as root or sudo
if [[ $EUID -ne 0 ]]; then
    echo "${RED}This script must be run as root or with sudo.${NC}"
    exit 1
fi

# IDEMPOTENCY CHECK: Exit if Splunk is already installed
if [ -d "$INSTALL_DIR" ]; then
  echo "${YELLOW}Splunk Universal Forwarder is already installed in $INSTALL_DIR. Aborting installation.${NC}"
  exit 0
fi

# Check the OS and install the necessary package
if [ -f /etc/os-release ]; then
  . /etc/os-release
else
  echo "${RED}Unable to detect the operating system. Aborting.${NC}"
  exit 1
fi

# Output detected OS
echo "${GREEN}Detected OS ID: $ID ${NC}"

# Function to create the Splunk user and group
create_splunk_user() {
  if ! id -u splunk &>/dev/null; then
    echo "${BLUE}Creating splunk user and group...${NC}"
    sudo groupadd splunk
    sudo useradd -r -g splunk -d $INSTALL_DIR splunk
  else
    echo "${GREEN}Splunk user already exists.${NC}"
  fi
}

# Function to install Splunk Forwarder
install_splunk() {
  local max_retries=3
  local retry_count=0
  local download_success=false

  echo "${BLUE}Downloading Splunk Forwarder tarball...${NC}"

  while [ $retry_count -lt $max_retries ] && [ $download_success = false ]; do
    if [ $retry_count -eq 0 ]; then
      # First attempt: Try with certificate verification
      wget -O $SPLUNK_PACKAGE_TGZ $SPLUNK_DOWNLOAD_URL
      local status=$?
    else
      # Subsequent attempts: Try without certificate verification
      echo "${YELLOW}Certificate verification failed, attempting download without certificate check...${NC}"
      wget --no-check-certificate -O $SPLUNK_PACKAGE_TGZ $SPLUNK_DOWNLOAD_URL
      local status=$?
    fi

    if [ $status -eq 0 ]; then
      download_success=true
    else
      retry_count=$((retry_count + 1))
      echo "${RED}Download failed (attempt $retry_count/$max_retries). Retrying in 5 seconds...${NC}"
      sleep 5
    fi
  done

  if [ $download_success = false ]; then
    echo "${RED}All download attempts failed. Aborting installation.${NC}"
    return 1
  fi

  echo "${BLUE}Extracting Splunk Forwarder tarball...${NC}"
  sudo tar -xvzf $SPLUNK_PACKAGE_TGZ -C /opt
  rm -f $SPLUNK_PACKAGE_TGZ

  echo "${BLUE}Setting permissions...${NC}"
  create_splunk_user
  sudo chown -R splunk:splunk $INSTALL_DIR
}


# Function to set admin credentials
set_admin_credentials() {
  echo "${BLUE}Setting admin credentials...${NC}"
  USER_SEED_FILE="$INSTALL_DIR/etc/system/local/user-seed.conf"
  sudo bash -c "cat > $USER_SEED_FILE" <<EOL
[user_info]
USERNAME = $ADMIN_USERNAME
PASSWORD = $ADMIN_PASSWORD
EOL
  sudo chown splunk:splunk $USER_SEED_FILE
  echo "${GREEN}Admin credentials set.${NC}"
}

# Function to set up a consolidated set of monitors
setup_monitors() {
  echo "${BLUE}Setting up consolidated monitors...${NC}"
  MONITOR_CONFIG="$INSTALL_DIR/etc/system/local/inputs.conf"
  
  # Consolidated list of monitors. Splunk will gracefully ignore files that do not exist on the host.
  MONITORS="
# -----------------------------------------------------------------------------
# System, Kernel, & Package Management
# -----------------------------------------------------------------------------

[monitor:///var/log/auth.log]
index = main
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/secure]
index = main
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/messages]
index = main
sourcetype = syslog
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/syslog]
index = main
sourcetype = syslog
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/kern.log]
index = main
sourcetype = linux_kernel
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/cron]
index = main
sourcetype = cron
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/yum.log]
index = main
sourcetype = package
crcSalt = <SOURCE>

[monitor:///var/log/apt/history.log]
index = main
sourcetype = package
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# Misc Security Services (Audit, Firewall, IDS, etc.)
# -----------------------------------------------------------------------------

[monitor:///var/log/audit/audit.log]
index = main
sourcetype = linux:audit
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/fail2ban.log]
index = main
sourcetype = fail2ban
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/ufw.log]
index = main
sourcetype = ufw
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/firewalld]
index = main
sourcetype = firewalld
crcSalt = <SOURCE>

[monitor:///var/log/suricata/fast.log]
index = main
sourcetype = suricata:fast
crcSalt = <SOURCE>

[monitor:///var/log/suricata/eve.json]
index = main
sourcetype = suricacata:eve
crcSalt = <SOURCE>

# For cron-driven YARA scans. The path may need to be adjusted.
[monitor:///var/log/yara_scans.log]
index = main
sourcetype = yara
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# # LMD (Linux Malware Detect). Combines ClamAV, Yara, and additional AV functionality.
# -----------------------------------------------------------------------------

#General logs
[monitor:///usr/local/maldetect/logs/event_log]
index = main
sourcetype = linux_av:events
crcSalt = <SOURCE>

#scan summaries
[monitor:///usr/local/maldetect/logs/scan_log]
index = main
sourcetype = linux_av:scan_summaries
crcSalt = <SOURCE>

#errors
[monitor:///usr/local/maldetect/logs/error_log]
index = main
sourcetype = linux_av:errors
crcSalt = <SOURCE>

#full detailed reports
[monitor:///usr/local/maldetect/sess/*]
index = main
sourcetype = linux_av:full_reports
crcSalt = <SOURCE>

# -----------------------------------------------------------------------------
# Wazuh SIEM
# -----------------------------------------------------------------------------

[monitor:///var/ossec/logs/ossec.log]
index = main
sourcetype = wazuh:agent
crcSalt = <SOURCE>

# The following monitors are for a Wazuh MANAGER host.
[monitor:///var/ossec/logs/api.log]
index = main
sourcetype = wazuh:api
crcSalt = <SOURCE>

# archives.log can be very high volume. Enable with caution.
# [monitor:///var/ossec/logs/archives.log]
# index = main
# sourcetype = wazuh:archives
# crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# Web Servers, Proxies, & Databases
# -----------------------------------------------------------------------------

[monitor:///var/log/nginx/access.log]
index = main
sourcetype = nginx:access
crcSalt = <SOURCE>

[monitor:///var/log/nginx/error.log]
index = main
sourcetype = nginx:error
crcSalt = <SOURCE>

[monitor:///var/log/haproxy.log]
index = main
sourcetype = haproxy:log
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/httpd/access_log]
index = main
sourcetype = apache:access
crcSalt = <SOURCE>

[monitor:///var/log/httpd/error_log]
index = main
sourcetype = apache:error
crcSalt = <SOURCE>

[monitor:///var/log/apache2/access.log]
index = main
sourcetype = apache:access
crcSalt = <SOURCE>

[monitor:///var/log/apache2/error.log]
index = main
sourcetype = apache:error
crcSalt = <SOURCE>

[monitor:///var/log/mariadb/mariadb.log]
index = main
sourcetype = mysql:error
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/postgresql/*.log]
index = main
sourcetype = postgresql:log
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/redis/redis-server.log]
index = main
sourcetype = redis
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/apache2/modsec_audit.log]
index = main
sourcetype = modsecurity
crcSalt = <SOURCE>

[monitor:///var/log/nginx/modsec_audit.log]
index = main
sourcetype = modsecurity
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# Infrastructure & Automation
# -----------------------------------------------------------------------------

[monitor:///var/log/salt/master]
index = main
sourcetype = salt:master
crcSalt = <SOURCE>

[monitor:///var/log/salt/minion]
index = main
sourcetype = salt:minion
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# Virtualization & Containers
# -----------------------------------------------------------------------------

[monitor:///var/log/pveproxy/access.log]
index = main
sourcetype = proxmox:access
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/lib/docker/containers/*/*.log]
index = main
sourcetype = docker:json
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# Application & Network Services
# -----------------------------------------------------------------------------

[monitor:///var/log/tomcat*/catalina.out]
index = main
sourcetype = tomcat:catalina
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/maillog]
index = main
sourcetype = postfix
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/dovecot.log]
index = main
sourcetype = dovecot
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/dns/queries]
index = main
sourcetype = bind:query
recursive = true
crcSalt = <SOURCE>

#Test log
[monitor:///tmp/test.log]
index = main
sourcetype = test
crcSalt = <SOURCE>
"

  # Write the configuration
  sudo bash -c "cat > $MONITOR_CONFIG" <<EOL
$MONITORS
EOL

  sudo chown splunk:splunk $MONITOR_CONFIG
  echo "${GREEN}Monitors configured.${NC}"
}

# Function to configure the forwarder to send logs to the Splunk indexer
configure_forwarder() {
  echo "${BLUE}Configuring Splunk Universal Forwarder to send logs to $INDEXER_IP:9997...${NC}"
  sudo $INSTALL_DIR/bin/splunk add forward-server $INDEXER_IP:9997 -auth $ADMIN_USERNAME:$ADMIN_PASSWORD
  echo "${GREEN}Forward-server configuration complete.${NC}"
}

# SIMPLIFIED: Function to restart Splunk using systemd
restart_splunk() {
  echo "${BLUE}Restarting Splunk Forwarder via systemd...${NC}"
  if sudo systemctl restart SplunkForwarder; then
    echo "${GREEN}Splunk Forwarder successfully restarted.${NC}"
    return 0
  else
    echo "${RED}Failed to restart Splunk. Please check logs for errors.${NC}"
    sudo systemctl status SplunkForwarder --no-pager # Show status on failure
    return 1
  fi
}

# --- Main Installation Logic ---

# Perform installation
install_splunk

# Set admin credentials before starting the service
set_admin_credentials

# Enable Splunk service and accept license agreement
if [ -d "$INSTALL_DIR/bin" ]; then
  echo "${BLUE}Starting and enabling Splunk Universal Forwarder service...${NC}"
  sudo $INSTALL_DIR/bin/splunk start --accept-license --answer-yes --no-prompt
  sudo $INSTALL_DIR/bin/splunk enable boot-start

  # Add monitors
  setup_monitors

  # Configure forwarder to send logs to the Splunk indexer
  configure_forwarder

  # Restart Splunk using our new function
  if ! restart_splunk; then
    echo "${RED}Splunk Forwarder restart failed. Installation incomplete.${NC}"
    exit 1
  fi
else
  echo "${RED}Installation directory not found. Something went wrong.${NC}"
  exit 1
fi

#Create test log
echo "${BLUE}Creating test log. ${NC}"
echo "Test log entry" > /tmp/test.log
sudo setfacl -m u:splunk:r /tmp/test.log

# Verify installation
sudo $INSTALL_DIR/bin/splunk version

echo "${YELLOW}Splunk Universal Forwarder v$SPLUNK_VERSION installation complete with monitors and forwarder configuration!${NC}"

# CentOS-specific fix using a systemd drop-in file
if [[ "$ID" == "centos" || "$ID_LIKE" == *"centos"* ]]; then
  echo "${RED}Applying CentOS-specific fix using systemd drop-in...${NC}"
  
  # Define the path for the drop-in file
  DROP_IN_DIR="/etc/systemd/system/SplunkForwarder.service.d"
  DROP_IN_FILE="$DROP_IN_DIR/override.conf"
  
  # Create the directory
  sudo mkdir -p "$DROP_IN_DIR"
  
  # Create the drop-in file to nullify AmbientCapabilities
  sudo bash -c "cat > $DROP_IN_FILE" <<EOL
[Service]
AmbientCapabilities=
EOL

  echo "${GREEN}Drop-in file created at $DROP_IN_FILE${NC}"
  
  # Reload systemd to apply the changes and restart Splunk
  echo "${BLUE}Reloading systemd daemon and restarting Splunk...${NC}"
  sudo systemctl daemon-reload
  sudo systemctl restart SplunkForwarder
  
  echo "${YELLOW}CentOS fix applied and Splunk restarted.${NC}}"
fi


# IMPROVED: Fedora specific fix.
#if [[ "$ID" == "fedora" ]]; then
#  echo "${YELLOW}Fedora system detected. Reloading systemd and restarting service to ensure stability...${NC}"
#  sudo systemctl daemon-reload
#  sudo systemctl restart SplunkForwarder
#fi

# --- OLD FEDORA FIX (COMMENTED OUT FOR POSTERITY) ---
#
# # Fedora specific fix. The forwarder doesn't like to work when you install it. For some reason, rebooting just solves this so nicely
# # I've looked for logs, tried starting it manually, etc. I couldn't figure it out and am running out of time. Therefore, this beautiful addition.
# # This will reboot the machine after a 10 second timer.
 if [[ "$ID" == "fedora" ]]; then
   echo "${RED}Fedora system detected, a reboot is required. System will reboot in 10 seconds.${NC}"
   sleep 10;
 
   # Reboot with 10 second delay
   if ! sudo shutdown -r +0 "${GREEN}First reboot attempt failed. System will reattempt in 5 seconds${NC}" & sleep 5; then
     echo "${RED}Warning: Graceful reboot failed, attempting forced reboot${NC}"
     if ! sudo reboot -f; then
       echo "${RED}Error: Unable to initiate reboot. Manual reboot required.${NC}"
       exit 1
     fi
   fi
   exit 0
 fi
