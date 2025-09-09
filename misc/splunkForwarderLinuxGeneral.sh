#!/bin/bash
# Automates the installation of the Splunk Universal Forwarder. Dynamically prompts for configuration.
# Works with Debian, Ubuntu, CentOS, Fedora, and Oracle Linux. It should work with more distros, but those are what it was tested with.

#You need to run this as sudo.

# This was put together as an amalgamation of code from my own work, other automatic installation scripts, and AI to tie everything together.
# Lots of time went into this script. Be nice to it plz <3
#
# Samuel Brucker 2025-2026

# Define Splunk Forwarder variables
SPLUNK_VERSION="9.1.1"
SPLUNK_BUILD="64e843ea36b1"
SPLUNK_PACKAGE_TGZ="splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-Linux-x86_64.tgz"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PACKAGE_TGZ}"
INSTALL_DIR="/opt/splunkforwarder"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Changeme1!"  # Replace with a secure password
RECEIVER_PORT="9997"

# Pretty colors :)
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'  #No Color - resets the color back to default

# Make sure this is being run as root or sudo
if [[ $EUID -ne 0 ]]; then
    echo "${RED}This script must be run as root or with sudo.${NC}"
    exit 1
fi

# Ask for Splunk Indexer IP
while true; do
  read -p "${YELLOW}Please enter the IP address of the Splunk Indexer/Server: ${NC}" INDEXER_IP
  if [[ -n "$INDEXER_IP" ]]; then
    break
  else
    echo "${RED}Indexer IP cannot be empty. Please try again.${NC}"
  fi
done

# Check the OS and install the necessary packages
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

# Function to set up user-defined monitors
setup_monitors() {
  echo "${BLUE}Setting up user-defined monitors...${NC}"
  MONITOR_CONFIG="$INSTALL_DIR/etc/system/local/inputs.conf"
  USER_MONITORS="" # Initialize empty string

  while true; do
    read -p "${YELLOW}Enter the full path of a file or directory to monitor (or press Enter to finish): ${NC}" FILE_PATH

    # Exit loop if input is empty
    if [ -z "$FILE_PATH" ]; then
      break
    fi

    # Check if the file or directory exists
    if [ ! -e "$FILE_PATH" ]; then
      echo "${RED}Warning: Path '$FILE_PATH' does not exist. Skipping.${NC}"
      continue
    fi

    echo "${GREEN}Adding '$FILE_PATH' to monitors.${NC}"
    # Append the monitor stanza to the variable. Using auto_high_volume for better generic line breaking.
    USER_MONITORS+=$(printf "[monitor://%s]\nindex = main\nsourcetype = auto_high_volume\ndisabled = false\n\n" "$FILE_PATH")
  done
  
  # Add a default monitor for /tmp/test.log for consistency with the original script's verification step
  USER_MONITORS+=$(printf "[monitor:///tmp/test.log]\nindex = main\nsourcetype = test\ndisabled = false\n\n")

  # Write the configuration only if monitors were added
  if [ -n "$USER_MONITORS" ]; then
    sudo bash -c "cat > $MONITOR_CONFIG" <<EOL
$USER_MONITORS
EOL
    sudo chown splunk:splunk $MONITOR_CONFIG
    echo "${GREEN}Monitors configured successfully.${NC}"
  else
    echo "${YELLOW}No custom monitors were specified.${NC}"
  fi
}

# Function to configure the forwarder to send logs to the Splunk indexer
configure_forwarder() {
  echo "${BLUE}Configuring Splunk Universal Forwarder to send logs to $INDEXER_IP:$RECEIVER_PORT...${NC}"
  sudo $INSTALL_DIR/bin/splunk add forward-server $INDEXER_IP:$RECEIVER_PORT -auth $ADMIN_USERNAME:$ADMIN_PASSWORD
  echo "${GREEN}Forward-server configuration complete.${NC}"
}

# Function to restart Splunk with timeout and retry handling
restart_splunk() {
  local max_attempts=3
  local attempt=1
  local timeout=30  # 30 seconds per attempt

  echo "${BLUE}Attempting to restart Splunk Forwarder...${NC}"

  while [ $attempt -le $max_attempts ]; do
    # Start Splunk in background and capture PID
    sudo $INSTALL_DIR/bin/splunk restart &>/dev/null &
    local splunk_pid=$!

    # Wait for timeout or process completion
    wait $splunk_pid &>/dev/null &
    local wait_pid=$!
    sleep $timeout
    kill $wait_pid &>/dev/null

    # Check if Splunk is running
    if sudo $INSTALL_DIR/bin/splunk status | grep -q "running"; then
      echo "${GREEN}Splunk Forwarder successfully restarted.${NC}"
      return 0
    fi

    # If we reach here, restart failed
    echo "${YELLOW}Attempt $attempt failed. Trying again...${NC}"
    attempt=$((attempt + 1))
    sleep 5  # Brief pause before retry
  done

  # If we reach here, all attempts failed
  echo "${RED}Failed to restart Splunk after $max_attempts attempts. Please check logs for errors.${NC}"
  return 1
}

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

# CentOS-specific fixes
if [[ "$ID" == "centos" || "$ID_LIKE" == *"centos"* ]]; then
  echo "${RED}Applying CentOS-specific fixes...${NC}"

  # Remove AmbientCapabilities line from the systemd service file
  # This needs to be performed on every reboot, because CentOS. This section makes sure it's applied at install, so it can run immediately.
  SERVICE_FILE="/etc/systemd/system/SplunkForwarder.service"
  if [ -f "$SERVICE_FILE" ]; then
    sudo sed -i '/AmbientCapabilities/d' "$SERVICE_FILE"
    echo "${GREEN}Removed AmbientCapabilities line from $SERVICE_FILE ${NC}"
  fi

  # Create a systemd service to handle the fix
  FIX_SERVICE_FILE="/etc/systemd/system/splunk-fix.service"

  # Create the service file
  cat > "$FIX_SERVICE_FILE" <<EOL
[Unit]
Description=Splunk Fix Service
Before=network-online.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/usr/bin/sed -i '/AmbientCapabilities/d' /etc/systemd/system/SplunkForwarder.service"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

  # Enable and start the fix service
  echo "${BLUE}Enabling and starting the fix service${NC}"
  sudo systemctl daemon-reload
  sudo systemctl enable splunk-fix.service
  sudo systemctl start splunk-fix.service

  # Verify the fix service status
  echo "${BLUE}Verifying fix service status: ${NC}"
  sudo systemctl status splunk-fix.service

  # Reload systemd daemon
  echo "${BLUE}Reloading systemctl daemons${NC}"
  sudo systemctl daemon-reload

  # Run Splunk again
  echo "${BLUE}Restarting the Splunk Forwarder${NC}"
  sudo systemctl restart SplunkForwarder

  echo "${YELLOW}Restart complete, forwarder installation on CentOS complete${NC}}"
else
  echo "${GREEN}Operating system not recognized as CentOS. Skipping CentOS fix.${NC}"
fi

# Fedora specific fix. The forwarder doesn't like to work when you install it. For some reason, rebooting just solves this so nicely
# I've looked for logs, tried starting it manually, etc. I couldn't figure it out and am running out of time. Therefore, this beautiful addition.
# This will reboot the machine after a 10 second timer.
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
