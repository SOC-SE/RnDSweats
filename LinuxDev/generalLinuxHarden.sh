#!/bin/bash
#
# Universal Linux Hardening Script (RHEL/Ubuntu) - No Firewall
# Usage: sudo ./harden_universal_v2.sh
#

set -u

# --- 0. OS DETECTION & PRE-CHECKS ---
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: Must be run as root."
   exit 1
fi

# Detect OS family for Package Manager & Service names
if [ -f /etc/debian_version ]; then
    OS_FAMILY="debian"
    GROUP_ADMIN="sudo"
    PKG_MGR="apt-get"
    echo "Detected Debian/Ubuntu system."
    export DEBIAN_FRONTEND=noninteractive
elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="rhel"
    GROUP_ADMIN="wheel"
    PKG_MGR="dnf"
    echo "Detected RHEL/CentOS system."
else
    echo "Unsupported OS. Exiting."
    exit 1
fi

# --- CONFIGURATION ---
LOG_DIR="/var/log/hardening"
LOG_FILE="$LOG_DIR/harden_$(date +%F).log"
mkdir -p $LOG_DIR
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "      STARTING UNIVERSAL HARDENING (NO FW)"
echo "==================================================="

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
            declare -g "$var_name=$pass1"
            break
        else
            echo "Passwords do not match or are empty. Try again."
        fi
    done
}

# --- 1. CREDENTIAL SETUP ---
echo "[+] Phase 1: User & Password Setup"
prompt_password "ROOT User" ROOT_PASS
prompt_password "Emergency Admin (bbob)" BBOB_PASS

# Check for sysadmin
if id "sysadmin" &>/dev/null; then
    prompt_password "SYSADMIN User" SYSADMIN_PASS
else
    SYSADMIN_PASS=""
fi

echo "Updating passwords..."
echo "root:$ROOT_PASS" | chpasswd

if [ -n "$SYSADMIN_PASS" ]; then
    echo "sysadmin:$SYSADMIN_PASS" | chpasswd
    echo "Updated sysadmin password."
fi

# Setup Emergency User
if ! id "bbob" &>/dev/null; then
    echo "Creating emergency admin 'bbob'..."
    useradd -m -s /bin/bash bbob
    echo "bbob:$BBOB_PASS" | chpasswd
    usermod -aG $GROUP_ADMIN bbob
else
    echo "Updating bbob password..."
    echo "bbob:$BBOB_PASS" | chpasswd
    usermod -aG $GROUP_ADMIN bbob
fi

# Lock standard passwordless accounts
passwd -l sync 2>/dev/null
passwd -l games 2>/dev/null
passwd -l lp 2>/dev/null

# --- 2. SSH HARDENING ---
echo "[+] Phase 2: SSH Hardening & Sanitization"

# Ensure SSH server is installed (just in case)
if [ "$OS_FAMILY" == "debian" ]; then
    dpkg -s openssh-server &>/dev/null || apt-get install -y openssh-server
elif [ "$OS_FAMILY" == "rhel" ]; then
    rpm -q openssh-server &>/dev/null || dnf install -y openssh-server
fi

SSH_CONF="/etc/ssh/sshd_config"

# Backup original config
cp $SSH_CONF "$SSH_CONF.bak_$(date +%s)"

# 1. Wipe ALL SSH Authorized Keys (Removes Red Team Persistence)
# We find every 'authorized_keys' file on the disk and delete it.
# Since you are using passwords, this forces Red Team to know the password to get back in.
echo "Wiping ALL authorized_keys files..."
find / -name "authorized_keys" -type f -delete 2>/dev/null

# 2. Secure sshd_config
# We use sed to force these values, whether they are currently commented out or set to yes.
echo "Securing sshd_config..."

# Disable Root Login
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' $SSH_CONF
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' $SSH_CONF

# Disable Empty Passwords
sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONF
sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONF

# Force Protocol 2
sed -i 's/^Protocol.*/Protocol 2/' $SSH_CONF
sed -i 's/^#Protocol.*/Protocol 2/' $SSH_CONF

# Disable X11 Forwarding (prevents GUI hijacking)
sed -i 's/^X11Forwarding.*/X11Forwarding no/' $SSH_CONF
sed -i 's/^#X11Forwarding.*/X11Forwarding no/' $SSH_CONF

# Reduce Max Auth Tries (Mitigates brute force speed)
sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' $SSH_CONF
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' $SSH_CONF

# Ensure settings exist if they weren't in the file at all
grep -q "^PermitRootLogin" $SSH_CONF || echo "PermitRootLogin no" >> $SSH_CONF
grep -q "^PermitEmptyPasswords" $SSH_CONF || echo "PermitEmptyPasswords no" >> $SSH_CONF
grep -q "^Protocol" $SSH_CONF || echo "Protocol 2" >> $SSH_CONF

echo "Restarting SSH..."
systemctl restart sshd || systemctl restart ssh

# --- 3. SYSTEM HARDENING ---
echo "[+] Phase 3: System Hardening"

echo "Setting Banners..."
echo "UNAUTHORIZED ACCESS PROHIBITED." > /etc/issue
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



echo "Running enumeration and tool normalization scripts"
bash masterEnum.sh >> "$LOG_FILE" 2>&1
bash normalizeTools.sh >> "$LOG_FILE"
echo "Scripts completed. Check $LOG_FILE for more details."


echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "Be sure to read through the enumeration report at /var/log/syst/ "
echo "Good luck!"
echo "==================================================="