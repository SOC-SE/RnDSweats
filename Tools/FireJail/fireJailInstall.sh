#!/bin/bash

# ====================================================================================
# FireJail Installation & Profile Seeding Script (Competition Edition + Tools)
#
# Automates installation and seeds profiles for:
# 1. Critical Services (Apache, Nginx, SQL, DNS)
# 2. Attack Tools (Nmap, Netcat, Curl, Tcpdump) - Hardened against abuse.
# ====================================================================================

# --- Script Configuration ---
set -e

# --- Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_message() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}--- $1 ---"${NC}; }

# --- Root User Check ---
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root. Please use sudo."
  exit 1
fi

# --- Step 1: System Detection ---
log_step "Step 1: System Detection & Installation"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=${ID_LIKE:-""}
else
    log_warning "Cannot determine OS. Aborting."
    exit 1
fi

# Determine OS Family
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID" == "linuxmint" || " $OS_ID_LIKE " == *"debian"* ]]; then
    PKG_MANAGER="apt-get"
    log_message "Detected Debian-based system ($OS_ID). Updating..."
    $PKG_MANAGER update > /dev/null
    $PKG_MANAGER install -y firejail
elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "centos" || "$OS_ID" == "ol" || "$OS_ID" == "rhel" || " $OS_ID_LIKE " == *"rhel"* ]]; then
    if command -v dnf &> /dev/null; then PKG_MANAGER="dnf"; else PKG_MANAGER="yum"; fi
    log_message "Detected RHEL-based system. Installing EPEL & Firejail..."
    [[ "$OS_ID" =~ (centos|rhel|almalinux|rocky|ol) ]] && $PKG_MANAGER install -y epel-release > /dev/null
    $PKG_MANAGER install -y firejail
else
    log_warning "Unsupported distribution: '$OS_ID'."
    exit 1
fi

# --- Step 2: Verification ---
log_step "Step 2: Verification"
if command -v firejail &> /dev/null; then
    VER=$(firejail --version | head -n 1)
    log_message "Installed: $VER"
else
    log_warning "FireJail installation failed."
    exit 1
fi

# --- Step 3: Seeding Server Profiles ---
log_step "Step 3: Seeding Server Profiles"
log_message "Creating default profiles for 10 common services..."

PROFILE_DIR="/etc/firejail"
mkdir -p "$PROFILE_DIR"

create_profile() {
    local name=$1
    local content=$2
    if [ ! -f "$PROFILE_DIR/$name" ]; then
        echo "$content" > "$PROFILE_DIR/$name"
        log_message "  + Created $name"
    else
        echo "  . Skipping $name (already exists)"
    fi
}

# --- SERVICE PROFILES (From previous steps) ---

# 1. Apache2
create_profile "apache2.profile" "
include /etc/firejail/server.profile
noblacklist /var/www
noblacklist /etc/apache2
noblacklist /var/log/apache2
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,chown,dac_override,fowner,gid,setgid,setuid,sys_chroot
"

# 2. Nginx
create_profile "nginx.profile" "
include /etc/firejail/server.profile
noblacklist /var/www
noblacklist /etc/nginx
noblacklist /var/log/nginx
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid,chown
"

# 3. HAProxy
create_profile "haproxy.profile" "
include /etc/firejail/server.profile
noblacklist /etc/haproxy
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid
"

# 4. Bind9
create_profile "named.profile" "
include /etc/firejail/server.profile
noblacklist /var/cache/bind
noblacklist /etc/bind
noblacklist /var/lib/bind
noblacklist /run/named
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid,sys_chroot
"

# 5. Dnsmasq
create_profile "dnsmasq.profile" "
include /etc/firejail/server.profile
noblacklist /var/lib/misc
noblacklist /var/lib/dnsmasq
noblacklist /etc/dnsmasq.conf
noblacklist /etc/dnsmasq.d
protocol unix,inet,inet6,netlink
caps.keep net_bind_service,setgid,setuid,net_admin,net_raw
seccomp
"

# 6. Redis
create_profile "redis-server.profile" "
include /etc/firejail/server.profile
noblacklist /var/lib/redis
noblacklist /etc/redis
noblacklist /var/log/redis
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid
"

# 7. Memcached
create_profile "memcached.profile" "
include /etc/firejail/server.profile
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid
"

# 8. Vsftpd
create_profile "vsftpd.profile" "
include /etc/firejail/server.profile
noblacklist /srv/ftp
noblacklist /var/ftp
noblacklist /etc/vsftpd.conf
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid,sys_chroot,audit_write
"

# 9. Squid
create_profile "squid.profile" "
include /etc/firejail/server.profile
noblacklist /var/spool/squid
noblacklist /var/log/squid
noblacklist /etc/squid
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid
"

# 10. Lighttpd
create_profile "lighttpd.profile" "
include /etc/firejail/server.profile
noblacklist /var/www
noblacklist /etc/lighttpd
noblacklist /var/log/lighttpd
protocol unix,inet,inet6
seccomp
caps.keep net_bind_service,setgid,setuid
"


# --- STEP 4: HARDENING DUAL-USE TOOLS ---
log_step "Step 4: Seeding & Hardening Dual-Use Tool Profiles"
log_message "Creating hardened profiles for Nmap, Ncat, Curl, etc..."

# 11. Ncat / Netcat (The "Anti-Reverse-Shell" Profile)
# This profile explicitly BLOCKS access to shells.
# Even if they run 'ncat -e /bin/bash', ncat cannot see /bin/bash.
NCAT_PROFILE="
include /etc/firejail/disable-common.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-passwdmgr.inc

# CRITICAL: Prevent reverse shells
blacklist /bin/sh
blacklist /bin/bash
blacklist /bin/dash
blacklist /bin/zsh
blacklist /usr/bin/sh
blacklist /usr/bin/bash

caps.drop all
netfilter
no3d
nodvd
nogroups
nonewprivs
noroot
nosound
notv
novideo
protocol unix,inet,inet6
seccomp
shell none
tracelog
"
create_profile "ncat.profile" "$NCAT_PROFILE"
create_profile "nc.profile" "$NCAT_PROFILE"
create_profile "netcat.profile" "$NCAT_PROFILE"


# 12. Nmap (The "Anti-Pivot" Profile)
# Allows scanning, but prevents writing files to sensitive areas or running exploits.
create_profile "nmap.profile" "
include /etc/firejail/disable-common.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-passwdmgr.inc

# Nmap needs root networking to scan efficiently
caps.keep net_raw,net_admin

# Prevent Nmap from reading SSH keys or Root's home
blacklist /root
blacklist /home/*/.ssh

# Prevent execution of other binaries (NSE script protection)
noexec /tmp
noexec /var/tmp
noexec /dev/shm

nosound
no3d
"


# 13. Curl / Wget (The "Safe Downloader" Profile)
# Prevents 'curl | bash' attacks by blocking shell execution context
DOWNLOADER_PROFILE="
include /etc/firejail/disable-common.inc
include /etc/firejail/disable-programs.inc

# Block executing downloaded files
noexec /tmp
noexec /home
noexec /var/tmp

caps.drop all
netfilter
seccomp
shell none
"
create_profile "curl.profile" "$DOWNLOADER_PROFILE"
create_profile "wget.profile" "$DOWNLOADER_PROFILE"


# 14. Tcpdump (The "Safe Sniffer" Profile)
create_profile "tcpdump.profile" "
include /etc/firejail/disable-common.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-passwdmgr.inc

caps.keep net_raw,net_admin
# Only allow writing to tmp, block writing to system dirs
whitelist /tmp
whitelist /var/tmp

seccomp
shell none
"

log_message "Tool hardening profiles seeded."

# --- Step 5: Post-Installation Instructions ---
echo -e "${BLUE}"
echo "======================================================================"
echo " Installation Complete!"
echo "======================================================================"
echo "1. Run the Scanner to auto-harden running services:"
echo "   sudo ./firejailScanner.sh"
echo ""
echo "2. Enforce Firejail for command line tools:"
echo "   Run 'sudo firecfg' to automatically sandbox nmap, curl, etc."
echo "   (This creates symlinks in /usr/local/bin so typing 'curl' uses Firejail)"
echo "======================================================================"
echo -e "${NC}"

exit 0