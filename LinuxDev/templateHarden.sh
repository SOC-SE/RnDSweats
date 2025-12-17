#!/bin/bash
#
# BASE LINUX HARDENING TEMPLATE (Oracle Linux 9.2)
#
# 1. Hardens OS (Users, Cron, Banner, Permissions)
# 2. Removes SSH (Anti-Red Team)
# 3. FIREWALL: Strict IPTables with OUTPUT DROP (Anti-Reverse Shell)
#
# Usage: ./harden_base.sh
#

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
BACKUP_DIR="/etc/BacService"
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/baseHarden.log"

# Create log dir
mkdir -p $LOG_DIR

# Redirect output to log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "          Starting Base System Hardening           "
echo "==================================================="

# --- PASSWORD PROMPTS ---
echo "--- CREDENTIAL SETUP ---"
prompt_password "ROOT User" ROOT_PASS
prompt_password "BBOB Backdoor User" BBOB_PASS

# Check if sysadmin exists before asking for password
if id "sysadmin" &>/dev/null; then
    prompt_password "SYSADMIN User" SYSADMIN_PASS
else
    echo "User 'sysadmin' not found. Skipping."
    SYSADMIN_PASS=""
fi
echo "------------------------"

# --- OS HARDENING ---
echo "[+] Phase 1: System Hardening"

echo "Changing System Passwords..."
echo "root:$ROOT_PASS" | chpasswd

if [ -n "$SYSADMIN_PASS" ]; then
    echo "sysadmin:$SYSADMIN_PASS" | chpasswd
    echo "Changed sysadmin password."
fi

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

# --- FIREWALL (STRICT MODE) ---
echo "[+] Phase 2: Firewall Configuration (Strict Output Control)"

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
# NOTE: INPUT rules are commented out by default on a generic box. 
#       Uncomment if this box is a Web Server.

# iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 100/min --limit-burst 200 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 600/min --limit-burst 500 -j ACCEPT

# iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 100/min --limit-burst 200 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 600/min --limit-burst 500 -j ACCEPT

# ==========================================
# [INSERT SERVICE SPECIFIC RULES HERE]
# ==========================================

# Example: MySQL/MariaDB (3306)
# iptables -A INPUT -p tcp --dport 3306 -m conntrack --ctstate NEW -j ACCEPT
# iptables -A OUTPUT -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Example: Mail (25/110/143)
# iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
# iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT


# ==========================================
# [END SERVICE SPECIFIC RULES]
# ==========================================

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

echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "==================================================="