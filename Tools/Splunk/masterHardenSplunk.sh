#!/bin/bash
#Hardening script for Splunk. Assumes some version of Oracle Linux 9.2
#
# Samuel Brucker 2024-2026

set -u

# --- HELPER FUNCTIONS ---
prompt_password() {
    local user_label=$1
    local var_name=$2
    while true; do
        echo -n "Enter new password for $user_label: "
        stty -echo
        read pass1
        stty echo
        echo
        echo -n "Confirm new password for $user_label: "
        stty -echo
        read pass2
        stty echo
        echo
        
        if [ "$pass1" == "$pass2" ] && [ -n "$pass1" ]; then
            eval "$var_name='$pass1'"
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
mkdir -p $LOG_DIR

# Redirect output to log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "            Starting Splunk Hardening              "
echo "==================================================="


#Enumeration
echo "Performing first enumeration cycle"



# --- PASSWORD PROMPTS (Gather all creds first) ---
echo "--- CREDENTIAL SETUP ---"

echo "Changing System Passwords..."

prompt_password "Root" ROOT_PASS
prompt_password "Bbob" BBOB_PASS
prompt_password "Splunk Admin" SPLUNK_PASSWORD
prompt_password "sysadmin" SYSADMIN_PASS



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
        cp -R "$SPLUNK_HOME/etc/licenses/*" "$BACKUP_DIR/licenses/" 
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
mkdir -p $SPLUNK_HOME/etc/system/local
cat > $SPLUNK_HOME/etc/system/local/user-seed.conf <<EOF
[user_info]
USERNAME = $SPLUNK_USERNAME
PASSWORD = $SPLUNK_PASSWORD
EOF
chown -R splunk:splunk $SPLUNK_HOME/etc/system/local

# Restore Licenses
if [ -d "$BACKUP_DIR/licenses" ]; then
    echo "Restoring licenses..."
    mkdir -p $SPLUNK_HOME/etc/licenses
    cp -r "$BACKUP_DIR/licenses/"* $SPLUNK_HOME/etc/licenses/
    chown -R splunk:splunk $SPLUNK_HOME/etc/licenses
fi

# First Start (Accept License)
echo "Initializing Splunk..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt

echo "Hardening Splunk keys and certs"

# C. Bind MongoDB to Localhost
echo "Locking down MongoDB..."
sed -i '$a [kvstore]\nbind_ip = 127.0.0.1' $SPLUNK_HOME/etc/system/local/server.conf

# D. Inputs (Forwarder/Syslog)
cat > $SPLUNK_HOME/etc/system/local/inputs.conf << EOF
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


#move the custom props.conf
chown splunk:splunk props.conf
mv props.conf $SPLUNK_HOME/etc/system/local/


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

# --- 5. FIREWALL (STRICT MODE) ---
echo "Configuring Firewall"

# Install IPTables services (Oracle 9 Standard)
dnf install -y iptables-services
systemctl stop firewalld
systemctl disable firewalld

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Set default policies
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP (Ping)
# RELAXED LIMITS: 20/s with burst of 50 to prevent blocking scoring engines
iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 0:192 -m limit --limit 20/s --limit-burst 50 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 0:192 -j LOG --log-prefix "Rate-limit exceeded: " --log-level 4
iptables -A INPUT -p icmp --icmp-type echo-request -m length ! --length 0:192 -j LOG --log-prefix "Invalid size: " --log-level 4
iptables -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 20/s --limit-burst 50 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Allow DNS traffic (Outbound UDP/TCP 53)
# RELAXED LIMITS: 200/min to allow dnf updates/bursts
iptables -A OUTPUT -p udp --dport 53 -m limit --limit 200/min --limit-burst 100 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m limit --limit 200/min --limit-burst 100 -j ACCEPT

# Allow HTTP/HTTPS traffic (Web Interface Access & Output for Updates)
# RELAXED OUTPUT: 600/min to ensure package downloads don't get throttled
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 100/min --limit-burst 200 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 600/min --limit-burst 500 -j ACCEPT

iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 100/min --limit-burst 200 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 600/min --limit-burst 500 -j ACCEPT

# Allow Splunk-specific traffic
# Splunk Web (8000)
iptables -A INPUT -p tcp --dport 8000 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8000 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Splunk Management (8089)
iptables -A INPUT -p tcp --dport 8089 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8089 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Splunk Forwarders (9997)
iptables -A INPUT -p tcp --dport 9997 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 9997 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Syslog (514)
iptables -A INPUT -p tcp --dport 514 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 514 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# --- WAZUH RULES ---
# Wazuh Agent Auth (1515) & Event (1514) & API (55000)

# Wazuh Event
iptables -A INPUT -p tcp --dport 1514 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 1514 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Wazuh Auth
iptables -A INPUT -p tcp --dport 1515 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 1515 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Wazuh API
iptables -A INPUT -p tcp --dport 55000 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 55000 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# --- SALT RULES ---
# Salt Master (4505/4506) & API (8881) & Custom GUI (3000)

# Salt Publish
iptables -A INPUT -p tcp --dport 4505 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 4505 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Salt Request
iptables -A INPUT -p tcp --dport 4506 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 4506 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Salt API
iptables -A INPUT -p tcp --dport 8881 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8881 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Salt Custom GUI
iptables -A INPUT -p tcp --dport 3000 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 3000 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROP-IN:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
iptables -A OUTPUT -j LOG --log-prefix "DROP-OUT:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence

echo "Saving IPTables rules..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Ensure Persistence on Oracle Linux
/usr/libexec/iptables/iptables.init save
systemctl enable iptables
systemctl start iptables


# --- FINAL CLEANUP ---
rm -f "$SPLUNK_PKG"
echo "==================================================="
echo "   OL9 and Splunk hardening complete. Good luck, Sam!"
echo "==================================================="