#!/bin/bash
set -euo pipefail
# =============================================================================
# SPLUNK FORWARDER INSTALLER (GENTOO / OPENRC EDITION)
# Based on Samuel Brucker's General Linux Script
# Adapted for CCDC Gentoo Environment
# =============================================================================

# --- Configuration ---
SPLUNK_VERSION="10.0.1"
SPLUNK_BUILD="c486717c322b"
SPLUNK_PACKAGE_TGZ="splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.tgz"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PACKAGE_TGZ}"
INSTALL_DIR="/opt/splunkforwarder"

# Defaults
DEFAULT_INDEXER_IP="172.20.242.20"
DEFAULT_ADMIN_USERNAME="admin"

# CLI Overrides
INDEXER_IP=${1:-$DEFAULT_INDEXER_IP}
ADMIN_USERNAME=${2:-$DEFAULT_ADMIN_USERNAME}
ADMIN_PASSWORD=${3:-}

# Prompt for password if not provided via CLI argument
if [[ -z "$ADMIN_PASSWORD" ]]; then
    echo "Enter password for Splunk admin user:"
    while true; do
        echo -n "Password: "
        stty -echo
        read -r pass1
        stty echo
        echo
        echo -n "Confirm password: "
        stty -echo
        read -r pass2
        stty echo
        echo
        if [[ "$pass1" == "$pass2" ]]; then
            ADMIN_PASSWORD="$pass1"
            break
        else
            echo "Passwords do not match. Please try again."
        fi
    done
fi

# Colors
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'

# --- 1. DEPENDENCY CHECK (GENTOO NATIVE) ---
install_dependencies() {
  echo "${BLUE}[*] Checking dependencies...${NC}"
  
  if command -v emerge &> /dev/null; then
      echo "${GREEN}    > Gentoo Portage detected.${NC}"
      
      # Check for wget, tar, setfacl (acl)
      # --noreplace prevents recompiling if already installed (Saves time!)
      echo "${BLUE}    > Ensuring wget, tar, and acl are installed...${NC}"
      # --ask=n for non-interactive mode (--ask n is invalid syntax)
      emerge --ask=n --noreplace net-misc/wget app-arch/tar sys-apps/acl
      
  elif command -v apt-get &> /dev/null; then
      # Fallback for Debian dev boxes
      apt-get update && apt-get install -y wget tar acl
  else
      echo "${RED}[!] Error: This script is optimized for Gentoo (emerge) or Debian (apt).${NC}"
      exit 1
  fi
}

# --- 2. USER CREATION ---
create_splunk_user() {
  if ! id -u splunk &>/dev/null; then
    echo "${BLUE}[*] Creating splunk user...${NC}"
    groupadd splunk 2>/dev/null
    useradd -r -g splunk -d "$INSTALL_DIR" splunk
  else
    echo "${GREEN}[*] Splunk user exists.${NC}"
  fi
}

# --- 3. INSTALLATION ---
install_splunk() {
  if [ -d "$INSTALL_DIR" ]; then
      echo "${GREEN}[*] Splunk already installed in $INSTALL_DIR.${NC}"
      return
  fi

  echo "${BLUE}[*] Downloading Splunk Forwarder...${NC}"
  wget --no-check-certificate -O "$SPLUNK_PACKAGE_TGZ" "$SPLUNK_DOWNLOAD_URL" || { echo "${RED}Download failed.${NC}"; exit 1; }

  echo "${BLUE}[*] Extracting...${NC}"
  tar -xzf "$SPLUNK_PACKAGE_TGZ" -C /opt
  rm -f "$SPLUNK_PACKAGE_TGZ"

  create_splunk_user
  chown -R splunk:splunk "$INSTALL_DIR"
}

# --- 4. CONFIGURATION ---
configure_splunk() {
  # Set Seed Config
  mkdir -p "$INSTALL_DIR/etc/system/local"
  cat > "$INSTALL_DIR/etc/system/local/user-seed.conf" <<EOL
[user_info]
USERNAME = $ADMIN_USERNAME
PASSWORD = $ADMIN_PASSWORD
EOL
  chown -R splunk:splunk "$INSTALL_DIR/etc/system/local"

  # Configure Forwarding
  echo "${BLUE}[*] Adding Forward Server: $INDEXER_IP:9997${NC}"
  # We use --accept-license here to prime the system
  sudo -u splunk "$INSTALL_DIR/bin/splunk" add forward-server "$INDEXER_IP:9997" -auth "$ADMIN_USERNAME:$ADMIN_PASSWORD" --accept-license --answer-yes --no-prompt
}

# --- 5. MONITORS (GENTOO ENHANCED) ---
setup_monitors() {
  echo "${BLUE}[*] Configuring Monitors...${NC}"
  MONITOR_FILE="$INSTALL_DIR/etc/system/local/inputs.conf"
  
  cat > "$MONITOR_FILE" <<EOL
# --- GENTOO SYSTEM LOGS ---
[monitor:///var/log/messages]
index = main
sourcetype = syslog
disabled = 0

[monitor:///var/log/emerge.log]
index = main
sourcetype = gentoo:emerge
disabled = 0

[monitor:///var/log/auth.log]
index = main
sourcetype = linux_secure
disabled = 0

[monitor:///var/log/secure]
index = main
sourcetype = linux_secure
disabled = 0

[monitor:///var/log/kern.log]
index = main
sourcetype = linux_kernel
disabled = 0

# --- SECURITY ---
[monitor:///var/log/audit/audit.log]
index = main
sourcetype = linux:audit
disabled = 0

[monitor:///var/log/fail2ban.log]
index = main
sourcetype = fail2ban
disabled = 0

[monitor:///var/log/rc.log]
index = main
sourcetype = openrc
disabled = 0

# --- WEB/DB ---
[monitor:///var/log/nginx/access.log]
index = main
sourcetype = nginx:access

[monitor:///var/log/apache2/access.log]
index = main
sourcetype = apache:access

[monitor:///var/log/mysql/mysql.log]
index = main
sourcetype = mysql:error

# --- CUSTOM ---
[monitor:///var/log/syst/hardening.log]
index = main
sourcetype = hardening_script
EOL

  chown splunk:splunk "$MONITOR_FILE"
}

# --- 6. SERVICE MANAGEMENT (OPENRC NATIVE) ---
manage_service() {
    echo "${BLUE}[*] Configuring Boot Start & Service...${NC}"
    
    # Let Splunk generate the init script
    # It usually detects /etc/init.d and places 'splunk' there
    "$INSTALL_DIR/bin/splunk" enable boot-start --accept-license --answer-yes --no-prompt --user splunk

    # GENTOO / OPENRC FIX
    if command -v rc-update &> /dev/null; then
        echo "${GREEN}    > OpenRC Detected. Adding Splunk to default runlevel...${NC}"
        rc-update add splunk default
        
        echo "${GREEN}    > Restarting Splunk via rc-service...${NC}"
        rc-service splunk restart || $INSTALL_DIR/bin/splunk restart
    
    # SYSTEMD FALLBACK
    elif command -v systemctl &> /dev/null; then
        echo "${GREEN}    > Systemd Detected.${NC}"
        systemctl enable SplunkForwarder
        systemctl restart SplunkForwarder
    else
        # Manual Fallback
        echo "${YELLOW}    > No init system detected. Starting manually.${NC}"
        sudo -u splunk "$INSTALL_DIR/bin/splunk" restart
    fi
}

# --- RUNTIME ---
if [[ $EUID -ne 0 ]]; then echo "${RED}Run as root.${NC}"; exit 1; fi

install_dependencies
install_splunk
configure_splunk
setup_monitors
manage_service

echo "${GREEN}==============================================${NC}"
echo "${GREEN}   GENTOO SPLUNK INSTALLATION COMPLETE        ${NC}"
echo "${GREEN}==============================================${NC}"