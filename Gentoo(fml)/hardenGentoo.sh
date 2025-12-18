#!/bin/bash
# =============================================================================
# GENTOO / UNIVERSAL HARDENING SUITE
#
# INCLUDES:
# 1. Base Hardening (Users, Passwords, Cron, Permissions)
# 2. SSH Hardening (Protocol 2, No Root, No Empty PW)
# 3. AUDITD Setup (Auto-install + Embedded Wazuh-Compatible Rules)
# 4. KERNEL Hardening (Sysctl Network Security)
# 5. SHELL Security (Timeouts & Immutable History)
#
# USAGE: ./gentooHarden.sh
# =============================================================================

set -u

# --- 0. HELPER FUNCTIONS ---

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

manage_service() {
    # Usage: manage_service <service_name> <action> (start|stop|restart|enable)
    local service=$1
    local action=$2
    
    echo "    > Performing '$action' on $service..."

    # 1. Systemd
    if command -v systemctl &> /dev/null && [ -d /run/systemd/system ]; then
        case $action in
            enable)  systemctl enable "$service" --now ;;
            disable) systemctl disable "$service" --now ;;
            *)       systemctl "$action" "$service" ;;
        esac

    # 2. OpenRC (Gentoo/Alpine)
    elif command -v rc-service &> /dev/null; then
        case $action in
            enable)  rc-update add "$service" default && rc-service "$service" start ;;
            disable) rc-service "$service" stop && rc-update delete "$service" default ;;
            *)       rc-service "$service" "$action" ;;
        esac
    fi
}

install_package() {
    local pkg=$1
    echo "    > Attempting to install $pkg..."
    
    if command -v emerge &> /dev/null; then
        # Gentoo: --noreplace saves time if already installed
        emerge --ask n --noreplace "$pkg"
    elif command -v apk &> /dev/null; then
        apk add "$pkg"
    elif command -v apt-get &> /dev/null; then
        apt-get update -y && apt-get install -y "$pkg"
    elif command -v dnf &> /dev/null; then
        dnf install -y "$pkg"
    elif command -v yum &> /dev/null; then
        yum install -y "$pkg"
    else
        echo "    ! ERROR: No package manager found for $pkg"
    fi
}

# --- PRE-CHECKS ---
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: Must be run as root."
   exit 1
fi

# --- CONFIGURATION VARIABLES ---
LOG_DIR="/var/log/hardening"
LOG_FILE="$LOG_DIR/gentoo_harden.log"
mkdir -p $LOG_DIR
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "          Starting Gentoo System Hardening         "
echo "==================================================="

# --- 1. CREDENTIAL SETUP ---
echo "--- CREDENTIAL SETUP ---"
prompt_password "ROOT User" ROOT_PASS
prompt_password "BBOB Backdoor User" BBOB_PASS
echo "------------------------"

# --- 2. OS HARDENING ---
echo "[+] Phase 1: Base System Hardening"

echo "Changing Root Password..."
echo "root:$ROOT_PASS" | chpasswd

echo "Creating 'bbob' user..."
if ! id "bbob" &>/dev/null; then
    useradd -m bbob
    # 'wheel' is the standard admin group on Gentoo/BSD
    usermod -aG wheel bbob 2>/dev/null || usermod -aG sudo bbob 2>/dev/null
fi
echo "bbob:$BBOB_PASS" | chpasswd

echo "Setting Legal Banners..."
cat > /etc/issue << EOF
UNAUTHORIZED ACCESS PROHIBITED. VIOLATORS WILL BE PROSECUTED.
EOF
cp /etc/issue /etc/motd

echo "Clearing Cron jobs..."
echo "" > /etc/crontab
# Nuke spool for all users (Dangerous but effective for comps)
rm -f /var/spool/cron/crontabs/* 2>/dev/null
rm -f /var/spool/cron/* 2>/dev/null
echo "    > Cron spools cleared."

echo "Restricting user creation tools..."
chmod 700 /usr/sbin/useradd
chmod 700 /usr/sbin/groupadd

echo "Locking down Cron and AT permissions..."
touch /etc/cron.allow /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# --- 3. SSH HARDENING ---
echo "[+] Phase 2: SSH Hardening"
SSH_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSH_CONFIG" ]; then
    cp $SSH_CONFIG "$SSH_CONFIG.bak"
    
    # Sed magic to enforce settings
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' $SSH_CONFIG
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' $SSH_CONFIG
    sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONFIG
    sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONFIG
    sed -i 's/^#Protocol.*/Protocol 2/' $SSH_CONFIG
    sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' $SSH_CONFIG
    sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' $SSH_CONFIG
    sed -i 's/^#X11Forwarding.*/X11Forwarding no/' $SSH_CONFIG
    
    echo "    > Restarting SSH..."
    manage_service "sshd" "restart"
else
    echo "    ! SSH Config not found. Is SSH installed?"
fi

# --- 4. KERNEL HARDENING (NEW) ---
echo "[+] Phase 3: Kernel Hardening (Sysctl)"
cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignore ICMP Broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable Source Packet Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Disable IP Forwarding (Prevents pivoting)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
# Log Martians
net.ipv4.conf.all.log_martians = 1
# Disable IPv6 if not needed (Optional, uncomment if safe)
# net.ipv6.conf.all.disable_ipv6 = 1
EOF

# Apply
sysctl -p /etc/sysctl.d/99-security.conf 2>/dev/null
echo "    > Sysctl rules applied."

# --- 5. SHELL SECURITY (NEW) ---
echo "[+] Phase 4: Shell Security"

# Set idle timeout to 5 minutes
if ! grep -q "TMOUT=300" /etc/profile; then
    echo "readonly TMOUT=300" >> /etc/profile
    echo "readonly HISTFILE" >> /etc/profile
    echo "chmod 600 /etc/profile" >> /etc/profile
    echo "    > Global shell timeout enabled (300s)."
fi

# Lock root history
touch /root/.bash_history
# chattr might be missing on minimal installs
if command -v chattr &> /dev/null; then
    chattr +a /root/.bash_history
    echo "    > Root history set to append-only (+a)."
fi

# --- 6. AUDITD SETUP (MERGED) ---
echo "[+] Phase 5: Auditd Installation & Configuration"

# A. Install Auditd
if ! command -v auditd &> /dev/null; then
    # Map 'auditd' to correct package name if needed (usually 'audit' or 'auditd')
    if command -v emerge &> /dev/null; then
        install_package "sys-process/audit"
    else
        install_package "auditd"
    fi
fi

# B. Generate Rules (Wazuh Compatible - No 'task' rule)
RULES_FILE="/etc/audit/rules.d/99-hardening.rules"
# Fallback for older systems
if [ ! -d "/etc/audit/rules.d" ]; then
    mkdir -p /etc/audit/rules.d
    # If no rules.d support, we might need to write to audit.rules directly, 
    # but modern distros use rules.d
fi

echo "    > Generating hardening rules..."
cat > "$RULES_FILE" << 'EOF'
# --- Self Auditing ---
-D
-b 8192
-f 1
-i
-w /var/log/audit/ -p wra -k auditlog
-w /etc/audit/ -p wa -k auditconfig

# --- Command Execution (The Big One) ---
-a always,exit -F arch=b64 -S execve -F key=execve
-a always,exit -F arch=b32 -S execve -F key=execve

# --- Network Connections (C2 Detection) ---
-a always,exit -F arch=b64 -S connect -F success=1 -k network_connect
-a always,exit -F arch=b32 -S connect -F success=1 -k network_connect

# --- User/Group Modifications ---
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# --- Sudoers ---
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# --- Suspicious Tools ---
-w /usr/bin/nc -p x -k susp_activity
-w /usr/bin/ncat -p x -k susp_activity
-w /usr/bin/wget -p x -k susp_activity
-w /usr/bin/curl -p x -k susp_activity
-w /usr/bin/socat -p x -k susp_activity

# --- File Deletion ---
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete

# --- Immutable ---
-e 2
EOF

# C. Load Rules
echo "    > Loading Audit Rules..."
# Fix SELinux context if present
if command -v restorecon &> /dev/null; then restorecon -v "$RULES_FILE"; fi

# Load
if command -v augenrules &> /dev/null; then
    augenrules --load
elif command -v auditctl &> /dev/null; then
    # Fallback if augenrules is missing
    auditctl -R "$RULES_FILE"
fi

# D. Enable & Restart
manage_service "auditd" "enable"
manage_service "auditd" "restart"

# --- 7. GENTOO SPECIFIC CHECKS ---
echo "[+] Phase 6: Gentoo Sanity Checks"

echo "[*] Auditing 'world' file..."
if [ -f "/var/lib/portage/world" ]; then
    grep -E "nmap|metasploit|netcat|wireshark|tcpdump|hydra" /var/lib/portage/world || echo "    > Clean."
fi

echo "[*] Auditing 'wheel' group..."
grep "wheel" /etc/group
echo "    > Verify only ROOT/BBOB are in wheel."

echo "==================================================="
echo "        GENTOO SYSTEM HARDENING COMPLETE"
echo "==================================================="
echo "Next Steps:"
echo "1. Run your 'firewallGenerator.sh' immediately."
echo "2. Re-login to verify SSH still works."