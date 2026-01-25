#!/bin/bash
#
# for ubuntu web
#
# Reminder: test this script before comp

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
rm -rf /var/spool/cron/*
rm -rf /var/spool/cron/crontabs/*

# 1. Wipe ALL SSH Authorized Keys (Removes Red Team Persistence)
# We find every 'authorized_keys' file on the disk and delete it.
# Since you are using passwords, this forces Red Team to know the password to get back in.
echo "Wiping ALL authorized_keys files..."
find / -name "authorized_keys" -type f -delete 2>/dev/null

# 2. Remove SSHD
echo "Removing sshd..."
apt remove openssh


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

echo "Restricting Permissions on Critical Compilers (Anti-Compile)..."
# Stops Red Team from compiling local privilege escalation exploits on the box
chmod 000 /usr/bin/gcc 2>/dev/null
chmod 000 /usr/bin/g++ 2>/dev/null
chmod 000 /usr/bin/make 2>/dev/null
chmod 000 /usr/bin/cc 2>/dev/null
chmod 000 /usr/bin/clang 2>/dev/null

echo "Removing SUID from dangerous binaries (GTFOBins mitigation)..."
# These binaries allow priv esc if they have SUID bit set. We strip it.
DANGEROUS_BINS="find vim nmap less awk sed python python3 perl ruby tar zip netcat nc man"
for bin in $DANGEROUS_BINS; do
    BINARY_PATH=$(which $bin 2>/dev/null)
    if [ -n "$BINARY_PATH" ]; then
        chmod u-s "$BINARY_PATH"
        echo "Removed SUID from $bin"
    fi
done

echo "Setting Kernel parameters (Sysctl)..."
# Prevent IP Spoofing
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
# Disable IP Source Routing
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
# Enable SYN Cookies (Syn Flood protection)
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# Disable ICMP Redirects (MITM mitigation)
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -p

# --- FIREWALL (STRICT MODE) ---
echo "[+] Phase 2: Firewall Configuration (Strict Output Control)"

# Base
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Input
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT

# Output
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Logging
iptables -A INPUT -m limit --limit 10/sec -j LOG --log-prefix "FW-DROP-IN: " --log-level 4
iptables -A OUTPUT -m limit --limit 10/sec -j LOG --log-prefix "FW-DROP-OUT: " --log-level 4

# Policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Save Rules
/usr/libexec/iptables/iptables.init save

# Run Other Scripts
echo "Running enumeration script"
bash masterEnum.sh >> "$LOG_FILE" 2>&1
echo "Running tool normalization script"
bash normalizeTools.sh >> "$LOG_FILE"

iptables -A OUTPUT -p tcp --dport 80 -j DROP
iptables -A OUTPUT -p tcp --dport 443 -j DROP

# Backups
TIMESTAMP=$(date +%Y%m%d%H%M%S)
mkdir -p "$BACKUP_DIR"

# Backup www directory
if [ -d /var/www ]; then
    echo "Backing up /var/www to $BACKUP_DIR..."
    tar -czpf "$BACKUP_DIR/www_backup_$TIMESTAMP.tar.gz" -C / var/www
    echo "Backup saved to $BACKUP_DIR/www_backup_$TIMESTAMP.tar.gz"
else
    echo "/var/www not found; skipping /var/www backup."
fi

# Backup apache configs
cp -r /etc/apache2 "$BACKUP_DIR/apache2_config_$TIMESTAMP" 2>/dev/null

# Backup mysql configs
cp -r /etc/mysql "$BACKUP_DIR/mysql_$TIMESTAMP"

echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "==================================================="
