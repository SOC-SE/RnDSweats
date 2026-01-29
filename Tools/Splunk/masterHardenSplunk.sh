#!/bin/bash
set -euo pipefail
#Hardening script for Splunk. Assumes some version of Oracle Linux 9.2
#
# Samuel Brucker 2024-2026

# Get script directory for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Global variable to hold prompted password (avoids eval)
_PROMPTED_PASS=""

# --- HELPER FUNCTIONS ---
# SECURITY: Uses global variable instead of eval to avoid command injection
prompt_password() {
    local user_label=$1
    _PROMPTED_PASS=""
    while true; do
        echo -n "Enter new password for $user_label: "
        stty -echo
        read -r pass1
        stty echo
        echo
        echo -n "Confirm new password for $user_label: "
        stty -echo
        read -r pass2
        stty echo
        echo

        if [ "$pass1" == "$pass2" ] && [ -n "$pass1" ]; then
            _PROMPTED_PASS="$pass1"
            break
        else
            echo "Passwords do not match or are empty. Please try again."
        fi
    done
}

# --- PRE-CHECKS ---
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: Must be run as root."
   exit 1
fi

# --- CONFIGURATION VARIABLES ---
SPLUNK_VERSION="10.0.1"
SPLUNK_BUILD="c486717c322b"
SPLUNK_HOME="/opt/splunk"
SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PKG}"
SPLUNK_USERNAME="admin"

BACKUP_DIR="/etc/BacService"
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/splunkHarden.log"

# Create log dir
mkdir -p "$LOG_DIR"

# Redirect output to log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "            Starting Splunk Hardening              "
echo "==================================================="


#Enumeration
echo "Performing first enumeration cycle"
ENUM_SCRIPT="$SCRIPT_DIR/../../enumeration/masterEnum.sh"
if [[ -f "$ENUM_SCRIPT" ]]; then
    bash "$ENUM_SCRIPT"
else
    echo "[WARN] masterEnum.sh not found at $ENUM_SCRIPT, skipping enumeration."
fi


# --- PASSWORD PROMPTS (Gather all creds first) ---
echo "--- CREDENTIAL SETUP ---"

echo "Changing System Passwords..."

prompt_password "Root"
ROOT_PASS="$_PROMPTED_PASS"

prompt_password "Bbob"
BBOB_PASS="$_PROMPTED_PASS"

prompt_password "Splunk Admin"
SPLUNK_PASSWORD="$_PROMPTED_PASS"

prompt_password "sysadmin"
SYSADMIN_PASS="$_PROMPTED_PASS"

echo "root:$ROOT_PASS" | chpasswd
echo "sysadmin:$SYSADMIN_PASS" | chpasswd

echo "Changed root and sysadmin passwords"

# Create Backdoor User 'bbob'
if ! id "bbob" &>/dev/null; then
    echo "Creating backup user..."
    useradd bbob
    echo "bbob:$BBOB_PASS" | chpasswd
    usermod -aG wheel bbob
else
    echo "Updating bbob password..."
    echo "bbob:$BBOB_PASS" | chpasswd
fi





echo "------------------------"

echo "Nuking and then reinstalling Splunk..."

# Backup original Splunk and licenses, then nuke
if [ -d "$SPLUNK_HOME" ]; then
    #licenses
    echo "Found existing Splunk. Backing up licenses..."
    mkdir -p "$BACKUP_DIR/licenses"
    if [ -d "$SPLUNK_HOME/etc/licenses" ]; then
        cp -R "$SPLUNK_HOME/etc/licenses/." "$BACKUP_DIR/licenses/"
    fi

    #base Splunk installation
    echo "Backing up base Splunk installation"
    mkdir -p "$BACKUP_DIR/splunkORIGINAL"
    cp -R "$SPLUNK_HOME" "$BACKUP_DIR/splunkORIGINAL"
    
    #nuke splunk
    echo "Stopping and Removing old Splunk..."
    $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
    pkill -f splunkd || true
    rm -rf "$SPLUNK_HOME"
    
    echo "Removing package..."
    dnf remove -y splunk
fi

# Download & Install
if [ ! -f "$SPLUNK_PKG" ]; then
    echo "Downloading Splunk $SPLUNK_VERSION..."
    wget -q -O "$SPLUNK_PKG" "$SPLUNK_URL"
fi

echo "Installing Splunk..."
dnf install -y "$SPLUNK_PKG"

# Create Admin User (Seed)
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = $SPLUNK_USERNAME
PASSWORD = $SPLUNK_PASSWORD
EOF
chown -R splunk:splunk "$SPLUNK_HOME/etc/system/local"

# Restore Licenses
if [ -d "$BACKUP_DIR/licenses" ] && [ "$(ls -A "$BACKUP_DIR/licenses" 2>/dev/null)" ]; then
    echo "Restoring licenses..."
    mkdir -p "$SPLUNK_HOME/etc/licenses"
    cp -r "$BACKUP_DIR/licenses/." "$SPLUNK_HOME/etc/licenses/"
    chown -R splunk:splunk "$SPLUNK_HOME/etc/licenses"
fi

# First Start (Accept License)
echo "Initializing Splunk..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt

echo "Hardening Splunk keys and certs"

# C. Bind MongoDB to Localhost
echo "Locking down MongoDB..."
sed -i '$a [kvstore]\nbind_ip = 127.0.0.1' "$SPLUNK_HOME/etc/system/local/server.conf"

# D. Inputs (Forwarder/Syslog)
cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << EOF
[default]
host = $(hostname)

# I prefer to use the listener command so that I can see it open in Splunk's listener page
# But I'm leaving the config here if anyone wants to do it from this file.
#[tcp://9997]
#index = main
#disabled = 0

[tcp://514]
sourcetype = syslog
index = main
disabled = 0
EOF


#move the custom props.conf if it exists
PROPS_CONF="$SCRIPT_DIR/props.conf"
if [[ -f "$PROPS_CONF" ]]; then
    chown splunk:splunk "$PROPS_CONF"
    mv "$PROPS_CONF" "$SPLUNK_HOME/etc/system/local/"
else
    echo "[WARN] props.conf not found at $PROPS_CONF, skipping."
fi


# Start Splunk Back Up 
echo "Starting Hardened Splunk..."
$SPLUNK_HOME/bin/splunk start
$SPLUNK_HOME/bin/splunk enable boot-start                                

# Add the 9997 listener using splunk CLI
echo "Enabling 9997 Listener..."
# We use the password variable captured earlier
$SPLUNK_HOME/bin/splunk enable listen 9997 -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"

# --- 4. OS HARDENING ---
echo "Hardening System"


echo "Setting Legal Banners..."
cat > /etc/issue << EOF
UNAUTHORIZED ACCESS PROHIBITED. VIOLATORS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW.
EOF
cp /etc/issue /etc/motd

echo "Clearing Cron jobs..."
echo "" > /etc/crontab
rm -f /var/spool/cron/*

echo "Removing SSH Server..."
dnf remove -y openssh-server

echo "Restricting user creation tools..."
chmod 700 /usr/sbin/useradd
chmod 700 /usr/sbin/groupadd

echo "Locking down Cron and AT permissions..."
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny

touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# --- 5. FIREWALL (STRICT IPTABLES) ---
echo "Configuring Firewall"

# Disable firewalld, use iptables only
dnf install -y iptables-services 2>/dev/null || yum install -y iptables-services 2>/dev/null || true
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Default policies (safety net behind explicit REJECT rules)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP (all - required by CCDC rules)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Anti-reconnaissance: Bad TCP flags
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -f -j DROP

# --- Outbound: DNS, HTTP, HTTPS (for updates/tooling) ---
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# --- Inbound: Splunk services ---
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT   # Splunk Web
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT   # Splunk Forwarders
iptables -A INPUT -p tcp --dport 514 -j ACCEPT    # Syslog

# --- Inbound: Wazuh ---
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT   # Wazuh Event
iptables -A INPUT -p tcp --dport 1515 -j ACCEPT   # Wazuh Auth
iptables -A INPUT -p tcp --dport 55000 -j ACCEPT  # Wazuh API

# --- Inbound: Salt ---
iptables -A INPUT -p tcp --dport 4505 -j ACCEPT   # Salt Publish
iptables -A INPUT -p tcp --dport 4506 -j ACCEPT   # Salt Request
iptables -A INPUT -p tcp --dport 8881 -j ACCEPT   # Salt API
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT   # Salt Custom GUI

# --- Inbound: DNS (Technitium) ---
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 5380 -j ACCEPT  # Technitium Web UI

# --- Logging for all dropped/rejected packets ---
iptables -A INPUT -j LOG --log-prefix "IPT-INPUT-REJECT: " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "IPT-OUTPUT-REJECT: " --log-level 4
iptables -A FORWARD -j LOG --log-prefix "IPT-FORWARD-REJECT: " --log-level 4

# --- Default REJECT ---
iptables -A INPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable

# Save rules
echo "Saving IPTables rules..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
/usr/libexec/iptables/iptables.init save 2>/dev/null || true
systemctl enable iptables 2>/dev/null || true
systemctl start iptables 2>/dev/null || true


# --- FINAL CLEANUP ---
rm -f "$SPLUNK_PKG"
echo "==================================================="
echo "   OL9 and Splunk hardening complete. Good luck, Sam!"
echo "==================================================="
