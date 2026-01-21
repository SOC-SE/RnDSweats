#!/bin/bash
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
#dnf install -y iptables-services
systemctl stop firewalld
systemctl disable firewalld


/usr/libexec/iptables/iptables.init save
systemctl enable iptables
systemctl start iptables

echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "==================================================="