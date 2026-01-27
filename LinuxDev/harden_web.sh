#!/bin/bash
#
# Hardening script for Ubuntu web servers
# Tested on: Ubuntu 20.04-24.04
#
# Samuel Brucker 2025-2026

set -euo pipefail

# --- SCRIPT DIRECTORY ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- HELPER FUNCTIONS ---
# Global password variable (set by prompt_password)
_PROMPTED_PASS=""

prompt_password() {
    local user_label="$1"
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
BACKUP_DIR="/etc/BacService"
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/baseHarden.log"

# Create log dir
mkdir -p "$LOG_DIR"

# Redirect output to log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "          Starting Base System Hardening           "
echo "==================================================="

# --- PASSWORD PROMPTS ---
echo "--- CREDENTIAL SETUP ---"
prompt_password "ROOT User"
ROOT_PASS="$_PROMPTED_PASS"

prompt_password "BBOB Backup User"
BBOB_PASS="$_PROMPTED_PASS"

# Check if sysadmin exists before asking for password
if id "sysadmin" &>/dev/null; then
    prompt_password "SYSADMIN User"
    SYSADMIN_PASS="$_PROMPTED_PASS"
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
# Ubuntu uses 'sudo' group, not 'wheel'
if ! id "bbob" &>/dev/null; then
    echo "Creating backup user..."
    useradd -m bbob
    echo "bbob:$BBOB_PASS" | chpasswd
    usermod -aG sudo bbob
else
    echo "Updating bbob password..."
    echo "bbob:$BBOB_PASS" | chpasswd
fi

echo "Setting Legal Banners..."
cat > /etc/issue << EOF
UNAUTHORIZED ACCESS PROHIBITED. VIOLATORS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW.
EOF
cp /etc/issue /etc/motd

echo "Nuking Cron jobs..."
# Allow root only
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
# Clear all existing user cron tables
rm -rf /var/spool/cron/*
rm -rf /var/spool/cron/crontabs/*
# Clear system-wide crontab content but keep file
echo "" > /etc/crontab

# 1. Wipe ALL SSH Authorized Keys (Removes Red Team Persistence)
# WARNING: This removes ALL authorized_keys including legitimate ones!
echo "Wiping ALL authorized_keys files..."
echo "WARNING: This removes all SSH keys including legitimate ones!"
# Backup first (timestamp is intentionally computed once for all files)
BACKUP_TS=$(date +%s)
find /home -name "authorized_keys" -type f -exec cp {} "{}.bak.${BACKUP_TS}" \; 2>/dev/null || true
find /root -name "authorized_keys" -type f -exec cp {} "{}.bak.${BACKUP_TS}" \; 2>/dev/null || true
# Now delete
find / -name "authorized_keys" -type f -delete 2>/dev/null || true

# 2. Remove SSHD (CAUTION: May lock you out if this is your only access method!)
# Comment out the next two lines if SSH is required for competition scoring
echo "Removing ssh..."
echo "WARNING: Removing SSH! Make sure you have console access!"
apt-get remove -y openssh-server || echo "openssh-server not installed or already removed"


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
    BINARY_PATH=$(which "$bin" 2>/dev/null)
    if [ -n "$BINARY_PATH" ]; then
        chmod u-s "$BINARY_PATH"
        echo "Removed SUID from $bin"
    fi
done

echo "Setting Kernel parameters (Sysctl)..."
# Use a dedicated hardening sysctl file to avoid duplicates
SYSCTL_HARDEN="/etc/sysctl.d/99-ccdc-hardening.conf"
cat > "$SYSCTL_HARDEN" << 'SYSCTL_EOF'
# CCDC Hardening - Network Security
# Prevent IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable IP Source Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Enable SYN Cookies (Syn Flood protection)
net.ipv4.tcp_syncookies = 1
# Disable ICMP Redirects (MITM mitigation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# IPv6 hardening
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignore bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Log martian packets
net.ipv4.conf.all.log_martians = 1
# Disable core dumps for SUID binaries
fs.suid_dumpable = 0
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2
# Restrict dmesg access
kernel.dmesg_restrict = 1
SYSCTL_EOF
sysctl -p "$SYSCTL_HARDEN"

# --- FIREWALL (STRICT MODE) ---
echo "[+] Phase 2: Firewall Configuration (Strict Output Control)"

# Backup existing rules before changes
IPTABLES_BACKUP="$BACKUP_DIR/iptables_pre_harden_$(date +%Y%m%d%H%M%S).rules"
mkdir -p "$BACKUP_DIR"
iptables-save > "$IPTABLES_BACKUP" 2>/dev/null || true
echo "Backed up iptables rules to: $IPTABLES_BACKUP"

# Flush existing rules for idempotency (safe to run multiple times)
iptables -F
iptables -X 2>/dev/null || true

# Base
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Input - Web Server Ports
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
# Uncomment below if MySQL needs to be accessible externally (not recommended)
#iptables -A INPUT -p tcp --dport 3306 -j ACCEPT

# Output
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1514 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1515 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 4505 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 4506 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# Logging
iptables -A INPUT -m limit --limit 10/sec -j LOG --log-prefix "FW-DROP-IN: " --log-level 4
iptables -A OUTPUT -m limit --limit 10/sec -j LOG --log-prefix "FW-DROP-OUT: " --log-level 4

# Policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Save Rules (Ubuntu uses netfilter-persistent)
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
else
    # Install if missing and save
    apt-get install -y iptables-persistent netfilter-persistent
    netfilter-persistent save
fi

# Run Other Scripts (use SCRIPT_DIR for reliable paths)
ENUM_SCRIPT="$SCRIPT_DIR/../enumeration/masterEnum.sh"
NORMALIZE_SCRIPT="$SCRIPT_DIR/../utilities/normalizeTools.sh"
OPENCART_SCRIPT="$SCRIPT_DIR/../services/web/opencart_hardener.sh"

if [[ -f "$ENUM_SCRIPT" ]]; then
    echo "Running enumeration script"
    bash "$ENUM_SCRIPT" >> "$LOG_FILE" 2>&1 || echo "Enumeration script had errors"
else
    echo "Enumeration script not found at $ENUM_SCRIPT, skipping"
fi

if [[ -f "$NORMALIZE_SCRIPT" ]]; then
    echo "Running tool normalization script"
    bash "$NORMALIZE_SCRIPT" >> "$LOG_FILE" 2>&1 || echo "Normalize script had errors"
else
    echo "Normalize script not found, skipping"
fi

if [[ -f "$OPENCART_SCRIPT" ]]; then
    echo "Running opencart hardening script"
    bash "$OPENCART_SCRIPT" >> "$LOG_FILE" 2>&1 || echo "Opencart hardening had errors"
else
    echo "Opencart hardening script not found, skipping"
fi
echo "Scripts completed. Check $LOG_FILE for more details."

# Backups
TIMESTAMP=$(date +%Y%m%d%H%M%S)
mkdir -p "$BACKUP_DIR"

# Backup www directory
if [[ -d /var/www ]]; then
    echo "Backing up /var/www to $BACKUP_DIR..."
    tar -czpf "$BACKUP_DIR/www_backup_$TIMESTAMP.tar.gz" -C / var/www
    echo "Backup saved to $BACKUP_DIR/www_backup_$TIMESTAMP.tar.gz"
else
    echo "/var/www not found; skipping /var/www backup."
fi

# Backup apache configs
if [[ -d /etc/apache2 ]]; then
    cp -r /etc/apache2 "$BACKUP_DIR/apache2_config_$TIMESTAMP" 2>/dev/null || true
fi

# Backup mysql/mariadb configs
if [[ -d /etc/mysql ]]; then
    cp -r /etc/mysql "$BACKUP_DIR/mysql_$TIMESTAMP" 2>/dev/null || true
elif [[ -f /etc/my.cnf ]]; then
    cp /etc/my.cnf "$BACKUP_DIR/my.cnf_$TIMESTAMP" 2>/dev/null || true
fi

echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "==================================================="
