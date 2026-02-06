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

# --- Service Admin Account ---
# Shared service account for remote management and monitoring
# TODO: rotate this password after initial setup
if ! id "svcadmin" &>/dev/null; then
    echo "Creating service admin account 'svcadmin'..."
    useradd -m -s /bin/bash svcadmin
    echo "svcadmin:Changeme1!" | chpasswd
    usermod -aG $GROUP_ADMIN svcadmin
    echo "Service account 'svcadmin' ready."
else
    echo "Service account 'svcadmin' already exists, resetting password..."
    echo "svcadmin:Changeme1!" | chpasswd
    usermod -aG $GROUP_ADMIN svcadmin
fi

# Lock standard passwordless accounts
passwd -l sync 2>/dev/null
passwd -l games 2>/dev/null
passwd -l lp 2>/dev/null


#
#  COMMENTED OUT BECAUSE WE MAY HAVE SSH AS A SCORED SERVICE IN THE FUTURE
#

# --- 2. SSH REMOVAL ---
#echo "[+] Phase 2: SSH Removal & Key Sanitization"

# 1. Wipe SSH Authorized Keys (Removes Red Team Persistence)
#echo "Wiping authorized_keys files..."
#find / -name "authorized_keys" -type f -delete 2>/dev/null || true

# 2. Stop and disable SSH service
#echo "Stopping and disabling SSH..."
#systemctl stop sshd 2>/dev/null || systemctl stop ssh 2>/dev/null || true
#systemctl disable sshd 2>/dev/null || systemctl disable ssh 2>/dev/null || true

#echo "SSH has been disabled. Use console access only."

# --- 3. SYSTEM HARDENING ---
echo "[+] Phase 3: System Hardening"

echo "Setting Banners..."
echo "UNAUTHORIZED ACCESS PROHIBITED. ALL ACTIVITY IS MONITORED AND RECORDED. VIOLATIONS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW." > /etc/issue
cp /etc/issue /etc/motd
cp /etc/issue /etc/issue.net

echo "Nuking Cron jobs..."
# Allow root only
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
# Clear all existing user cron tables
rm -rf /var/spool/cron/*
rm -rf /var/spool/cron/crontabs/*
# Strip job lines from system crontab but keep variable definitions (SHELL, PATH, MAILTO, etc.)
if [[ -f /etc/crontab ]]; then
    grep -E '^\s*(#|SHELL=|PATH=|MAILTO=|HOME=|LOGNAME=|$)' /etc/crontab > /tmp/crontab_clean || true
    mv /tmp/crontab_clean /etc/crontab
    chmod 644 /etc/crontab
fi

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
SYSCTL_HARDEN="/etc/sysctl.d/99-security-hardening.conf"

# Backup existing file if present
[[ -f "$SYSCTL_HARDEN" ]] && cp "$SYSCTL_HARDEN" "${SYSCTL_HARDEN}.backup"

cat > "$SYSCTL_HARDEN" << 'SYSCTL_EOF'
# ==============================================================================
# Kernel Hardening - Sysctl Configuration
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

# Restrict non-essential service accounts to nologin and remove group memberships
for acct in svcadmin; do
    usermod -s /usr/sbin/nologin "$acct" 2>/dev/null || true
    gpasswd -d "$acct" sudo 2>/dev/null || true
    gpasswd -d "$acct" wheel 2>/dev/null || true
done



echo "Running enumeration and tool normalization scripts"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/masterEnum.sh" >> "$LOG_FILE" 2>&1
bash "$SCRIPT_DIR/../../postHardenTools/normalizeToolsGeneral.sh" >> "$LOG_FILE" 2>&1
bash "$SCRIPT_DIR/../../postHardenTools/normalizeToolsSecurity.sh" >> "$LOG_FILE" 2>&1
echo "Scripts completed. Check $LOG_FILE for more details."


echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "Be sure to read through the enumeration report at /var/log/syst/ "
echo "Good luck!"
echo "==================================================="