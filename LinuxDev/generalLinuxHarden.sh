#!/bin/bash
#
# Universal Linux Hardening Script (RHEL/Ubuntu) - No Firewall
# Usage: sudo ./harden_universal_v2.sh
#

set -euo pipefail

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
    # shellcheck disable=SC2034  # PKG_MGR used for reference/future expansion
    PKG_MGR="dnf"
    echo "Detected RHEL/CentOS system."
else
    echo "Unsupported OS. Exiting."
    exit 1
fi

# --- CONFIGURATION ---
LOG_DIR="/var/log/syst"
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
        read -r pass1
        stty echo
        echo
        echo -n "Confirm new password for $user_label: "
        stty -echo
        read -r pass2
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

# 1. Wipe SSH Authorized Keys (Removes Red Team Persistence)
# We find 'authorized_keys' files and delete them, but SKIP the vagrant user
# to avoid breaking Vagrant/development environments.
echo "Wiping authorized_keys files (preserving vagrant user for dev environments)..."
find / -name "authorized_keys" -type f ! -path "/home/vagrant/*" ! -path "/root/.ssh/*" -delete 2>/dev/null || true
# Note: To also wipe root's keys in production, remove the ! -path "/root/.ssh/*" exclusion
# Warning: This will lock out any SSH key-based access except vagrant

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
    BINARY_PATH=$(which "$bin" 2>/dev/null)
    if [ -n "$BINARY_PATH" ]; then
        chmod u-s "$BINARY_PATH"
        echo "Removed SUID from $bin"
    fi
done

echo "Setting Kernel parameters (Sysctl)..."
# Comprehensive kernel hardening via sysctl
SYSCTL_HARDEN="/etc/sysctl.d/99-ccdc-hardening.conf"

# Backup existing file if present
[[ -f "$SYSCTL_HARDEN" ]] && cp "$SYSCTL_HARDEN" "${SYSCTL_HARDEN}.backup"

cat > "$SYSCTL_HARDEN" << 'SYSCTL_EOF'
# ==============================================================================
# CCDC Kernel Hardening - Sysctl Configuration
# ==============================================================================

# --- NETWORK SECURITY - IPv4 ---
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# --- IPv6 - DISABLE (competition is IPv4-only) ---
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# --- KERNEL SECURITY ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1

# --- FILESYSTEM SECURITY ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# --- MEMORY SECURITY ---
vm.mmap_min_addr = 65536
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
SYSCTL_EOF

# Apply settings (some may fail on certain kernels, that's OK)
sysctl -p "$SYSCTL_HARDEN" >/dev/null 2>&1 || sysctl -p "$SYSCTL_HARDEN" 2>&1 | grep -v "^sysctl:" || true
echo "Kernel hardening applied: $SYSCTL_HARDEN"



echo "Running enumeration and tool normalization scripts"
bash masterEnum.sh >> "$LOG_FILE" 2>&1
bash normalizeTools.sh >> "$LOG_FILE"
echo "Scripts completed. Check $LOG_FILE for more details."


echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "Be sure to read through the enumeration report at /var/log/syst/ "
echo "Good luck!"
echo "==================================================="