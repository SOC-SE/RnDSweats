#!/bin/bash
# ==============================================================================
# Script Name: master-splunk-server.sh
# Description: Master hardening script for Splunk/SIEM Server
#              This is the CRITICAL infrastructure box - handles with care
#              Backs up + reinstalls Splunk fresh, hardens OS, configures firewall
# Target: Oracle Linux 9.2 / Rocky Linux 9 - Splunk Server
#         (also hosts SaltGUI, Wazuh, Technitium DNS)
# Author: Security Team
# Date: 2025-2026
# Version: 2.0
#
# Workflow:
#   1. Initial enumeration
#   2. Credential setup
#   3. Splunk backup, nuke, fresh install, restore licenses
#   4. Splunk configuration (listeners, props.conf, MongoDB)
#   5. OS hardening (banners, cron, SSH removal, user restrictions)
#   6. Disable/remove cockpit and firewalld
#   7. Strict iptables firewall
#   8. Kernel hardening (sysctl)
#   9. PAM audit
#   10. System backups + baseline
#   11. Post-hardening enumeration
#
# Services Protected: Splunk (8000, 9997), Syslog (514),
#                     Wazuh (1514, 1515, 55000), Salt (4505, 4506, 8881, 3000),
#                     DNS (53, 5380)
#
# Usage:
#   ./master-splunk-server.sh
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LINUXDEV="$SCRIPT_DIR/modules"
TOOLS="$REPO_DIR/Tools"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/master-splunk-server_$TIMESTAMP.log"

# Splunk configuration
SPLUNK_VERSION="10.0.2"
SPLUNK_BUILD="e2d18b4767e9"
SPLUNK_HOME="/opt/splunk"
SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PKG}"
SPLUNK_USERNAME="admin"

BACKUP_DIR="/etc/BacService"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helper Functions ---
log() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
phase() { echo -e "\n${CYAN}========== $1 ==========${NC}" | tee -a "$LOG_FILE"; }

# Global variable to hold prompted password (avoids eval)
_PROMPTED_PASS=""

prompt_password() {
    local user_label=$1
    _PROMPTED_PASS=""
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

run_script() {
    local script="$1"
    local name="$2"

    if [[ -f "$script" ]]; then
        log "Running $name..."
        chmod +x "$script"
        bash "$script" 2>&1 | tee -a "$LOG_FILE"
        log "$name completed"
    else
        warn "Script not found: $script"
    fi
}

# --- Pre-checks ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root"
    exit 1
fi

mkdir -p "$LOG_DIR"

# Redirect output to log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "========================================================"
echo "  SPLUNK/SIEM SERVER - MASTER HARDENING SCRIPT"
echo "  Target: Oracle Linux 9.2"
echo "  Time: $(date)"
echo "  WARNING: Critical infrastructure - proceed carefully!"
echo "========================================================"
echo ""

# ============================================================================
# PHASE 1: INITIAL ENUMERATION
# ============================================================================
phase "PHASE 1: INITIAL ENUMERATION"
log "Capturing pre-hardening system state..."

if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    chmod +x "$LINUXDEV/masterEnum.sh"
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_pre_$TIMESTAMP.log"
    log "Pre-hardening enumeration saved to $LOG_DIR/enum_pre_$TIMESTAMP.log"
fi

# ============================================================================
# PHASE 2: CREDENTIAL SETUP
# ============================================================================
phase "PHASE 2: CREDENTIAL SETUP"
log "Setting up credentials for system and Splunk..."

prompt_password "Root"
ROOT_PASS="$_PROMPTED_PASS"

prompt_password "Bbob (backup user)"
BBOB_PASS="$_PROMPTED_PASS"

prompt_password "Splunk Admin"
SPLUNK_PASSWORD="$_PROMPTED_PASS"

prompt_password "sysadmin"
SYSADMIN_PASS="$_PROMPTED_PASS"

echo "root:$ROOT_PASS" | chpasswd
echo "sysadmin:$SYSADMIN_PASS" | chpasswd
log "Changed root and sysadmin passwords"

# Create backup user 'bbob'
if ! id "bbob" &>/dev/null; then
    log "Creating backup user bbob..."
    useradd bbob
    echo "bbob:$BBOB_PASS" | chpasswd
    usermod -aG wheel bbob
else
    log "Updating bbob password..."
    echo "bbob:$BBOB_PASS" | chpasswd
fi

# ============================================================================
# PHASE 3: SPLUNK BACKUP, NUKE, REINSTALL
# ============================================================================
phase "PHASE 3: SPLUNK BACKUP, NUKE & REINSTALL"
log "This removes red team persistence from the original Splunk installation."

# Backup original Splunk and licenses, then nuke
if [ -d "$SPLUNK_HOME" ]; then
    log "Found existing Splunk. Backing up licenses..."
    mkdir -p "$BACKUP_DIR/licenses"
    if [ -d "$SPLUNK_HOME/etc/licenses" ]; then
        cp -R "$SPLUNK_HOME/etc/licenses/." "$BACKUP_DIR/licenses/"
    fi

    log "Backing up base Splunk installation..."
    mkdir -p "$BACKUP_DIR/splunkORIGINAL"
    cp -R "$SPLUNK_HOME" "$BACKUP_DIR/splunkORIGINAL"

    log "Stopping and removing old Splunk..."
    $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
    pkill -f splunkd || true
    rm -rf "$SPLUNK_HOME"

    log "Removing Splunk package..."
    dnf remove -y splunk 2>/dev/null || rpm -e splunk 2>/dev/null || true
fi

# Download fresh Splunk
if [ ! -f "$SPLUNK_PKG" ]; then
    log "Downloading Splunk $SPLUNK_VERSION..."
    wget -q -O "$SPLUNK_PKG" "$SPLUNK_URL"
fi

log "Installing fresh Splunk $SPLUNK_VERSION..."
dnf install -y "$SPLUNK_PKG" 2>/dev/null || rpm -i "$SPLUNK_PKG" 2>/dev/null

# Create admin user via seed
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = $SPLUNK_USERNAME
PASSWORD = $SPLUNK_PASSWORD
EOF
chown -R splunk:splunk "$SPLUNK_HOME/etc/system/local"

# Restore licenses from backup
if [ -d "$BACKUP_DIR/licenses" ] && [ "$(ls -A "$BACKUP_DIR/licenses" 2>/dev/null)" ]; then
    log "Restoring licenses..."
    mkdir -p "$SPLUNK_HOME/etc/licenses"
    cp -r "$BACKUP_DIR/licenses/." "$SPLUNK_HOME/etc/licenses/"
    chown -R splunk:splunk "$SPLUNK_HOME/etc/licenses"
fi

# First start (accept license)
log "Initializing Splunk (first start)..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt

$SPLUNK_HOME/bin/splunk add index linux -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"
$SPLUNK_HOME/bin/splunk add index windows -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"
$SPLUNK_HOME/bin/splunk add index network -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"

# ============================================================================
# PHASE 4: SPLUNK CONFIGURATION
# ============================================================================
phase "PHASE 4: SPLUNK CONFIGURATION"

# Lock down MongoDB to localhost
log "Locking down MongoDB..."
sed -i '$a [kvstore]\nbind_ip = 127.0.0.1' "$SPLUNK_HOME/etc/system/local/server.conf"

# Configure inputs (syslog on 514)
log "Configuring inputs.conf..."
cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << EOF
[default]
host = $(hostname)

[tcp://514]
sourcetype = ngfw:syslog
index = network
disabled = 0

[tcp://5140]
sourcetype = technitium:syslog
index = network
disabled = 0
connection_host = ip

# =============================================================================
# Local file monitors (logs generated on this host)
# =============================================================================

# --- System logs ---

[monitor:///var/log/auth.log]
index = linux
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/secure]
index = linux
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/messages]
index = linux
sourcetype = syslog
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/audit/audit.log]
index = linux
sourcetype = linux:audit
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# --- Custom scripts (syst) ---

[monitor:///var/log/syst/*audit*]
index = linux
sourcetype = linux_enume
crcSalt = <SOURCE>

[monitor:///var/log/syst/security_scan_*.log]
index = linux
sourcetype = linux_security_scan
crcSalt = <SOURCE>

[monitor:///var/log/syst/linpeas_findings_*.log]
index = linux
sourcetype = linpeas
crcSalt = <SOURCE>

[monitor:///var/log/syst/integrity_scan.log]
index = linux
sourcetype = linux_rootkit
crcSalt = <SOURCE>

[monitor:///var/log/syst/pre_install_compromise.log]
index = linux
sourcetype = linux_rootkit
crcSalt = <SOURCE>

# --- LMD (Linux Malware Detect) ---

[monitor:///usr/local/maldetect/logs/event_log]
index = linux
sourcetype = linux_av:events
crcSalt = <SOURCE>

[monitor:///usr/local/maldetect/logs/scan_log]
index = linux
sourcetype = linux_av:scan_summaries
crcSalt = <SOURCE>

[monitor:///usr/local/maldetect/logs/error_log]
index = linux
sourcetype = linux_av:errors
crcSalt = <SOURCE>

[monitor:///usr/local/maldetect/sess/*]
index = linux
sourcetype = linux_av:full_reports
crcSalt = <SOURCE>

# --- Wazuh (local manager logs) ---

[monitor:///var/ossec/logs/ossec.log]
index = linux
sourcetype = wazuh:agent
crcSalt = <SOURCE>

[monitor:///var/ossec/logs/api.log]
index = linux
sourcetype = wazuh:api
crcSalt = <SOURCE>

# Wazuh Agent Alerts (JSON - aggregated from all agents on this server)
[monitor:///var/ossec/logs/alerts/alerts.json]
index = linux
sourcetype = wazuh:alerts
crcSalt = <SOURCE>
disabled = 0

# --- Salt Master ---

[monitor:///var/log/salt/master]
index = linux
sourcetype = salt:master
crcSalt = <SOURCE>

# --- Technitium DNS (Docker container, host-mounted volume) ---
# NOTE: Query logging must be enabled in Technitium Web UI:
#       Settings > Logging > Enable "Log all queries"

[monitor:///opt/technitium-dns/config/logs/*.log]
index = linux
sourcetype = technitium:querylog
crcSalt = <SOURCE>
EOF

# Move custom props.conf if it exists
# Check multiple locations since script may run from /tmp or from repo
PROPS_CONF=""
for props_path in "$REPO_DIR/linux/securityInfrastructure/Splunk/props.conf" "$TOOLS/Splunk/props.conf" "$SCRIPT_DIR/props.conf" "$SCRIPT_DIR/../Tools/Splunk/props.conf" "/tmp/props.conf"; do
    if [[ -f "$props_path" ]]; then
        PROPS_CONF="$props_path"
        break
    fi
done

if [[ -n "$PROPS_CONF" ]]; then
    log "Installing custom props.conf from $PROPS_CONF..."
    cp "$PROPS_CONF" "$SPLUNK_HOME/etc/system/local/"
    chown splunk:splunk "$SPLUNK_HOME/etc/system/local/props.conf"
else
    warn "props.conf not found. Checked: $REPO_DIR/linux/securityInfrastructure/Splunk/, $TOOLS/Splunk/, $SCRIPT_DIR/, /tmp/"
fi

# Move custom transforms.conf if it exists
TRANSFORMS_CONF=""
for transforms_path in "$REPO_DIR/linux/securityInfrastructure/Splunk/transforms.conf" "$TOOLS/Splunk/transforms.conf" "$SCRIPT_DIR/transforms.conf" "/tmp/transforms.conf"; do
    if [[ -f "$transforms_path" ]]; then
        TRANSFORMS_CONF="$transforms_path"
        break
    fi
done

if [[ -n "$TRANSFORMS_CONF" ]]; then
    log "Installing custom transforms.conf from $TRANSFORMS_CONF..."
    cp "$TRANSFORMS_CONF" "$SPLUNK_HOME/etc/system/local/"
    chown splunk:splunk "$SPLUNK_HOME/etc/system/local/transforms.conf"
else
    warn "transforms.conf not found. Skipping..."
fi

# Deploy Splunk dashboards if they exist
DASHBOARDS_DIR=""
DASHBOARD_COUNT=0
for dash_path in "$REPO_DIR/linux/securityInfrastructure/Splunk/Dashboards" "$TOOLS/Splunk/Dashboards" "$SCRIPT_DIR/Dashboards" "/tmp/Splunk/Dashboards"; do
    if [[ -d "$dash_path" ]]; then
        DASHBOARDS_DIR="$dash_path"
        break
    fi
done

# Always create views directory (needed for manual imports too)
mkdir -p "$SPLUNK_HOME/etc/apps/search/local/data/ui/views"
chown -R splunk:splunk "$SPLUNK_HOME/etc/apps/search/local/data/ui"

if [[ -n "$DASHBOARDS_DIR" ]] && [[ -n "$(ls -A "$DASHBOARDS_DIR"/*.xml 2>/dev/null)" ]]; then
    log "Installing Splunk dashboards from $DASHBOARDS_DIR..."
    cp "$DASHBOARDS_DIR"/*.xml "$SPLUNK_HOME/etc/apps/search/local/data/ui/views/"
    chown splunk:splunk "$SPLUNK_HOME/etc/apps/search/local/data/ui/views"/*.xml
    DASHBOARD_COUNT=$(ls "$DASHBOARDS_DIR"/*.xml 2>/dev/null | wc -l)
    log "Dashboards installed: $DASHBOARD_COUNT files"
else
    warn "Dashboard directory not found or empty. Dashboards can be imported manually via Splunk Web UI."
    log "Views directory created at: $SPLUNK_HOME/etc/apps/search/local/data/ui/views/"
fi

# Restart Splunk with new config
log "Starting hardened Splunk..."
$SPLUNK_HOME/bin/splunk start
$SPLUNK_HOME/bin/splunk enable boot-start

# Enable 9997 listener via CLI
log "Enabling 9997 forwarder listener..."
$SPLUNK_HOME/bin/splunk enable listen 9997 -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"

log "Splunk reinstallation and configuration complete."

# ============================================================================
# PHASE 5: OS HARDENING
# ============================================================================
phase "PHASE 5: OS HARDENING"

# Legal banners
log "Setting legal banners..."
cat > /etc/issue << EOF
UNAUTHORIZED ACCESS PROHIBITED. VIOLATORS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW.
EOF
cp /etc/issue /etc/motd

# Cron lockdown
log "Clearing cron jobs and locking down..."
echo "" > /etc/crontab
rm -f /var/spool/cron/*

touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny

touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# SSH removal
log "Removing SSH server..."
dnf remove -y openssh-server 2>/dev/null || yum remove -y openssh-server 2>/dev/null || true
find / -name "authorized_keys" -type f -delete 2>/dev/null || true

# Restrict user creation tools
log "Restricting user creation tools..."
chmod 700 /usr/sbin/useradd
chmod 700 /usr/sbin/groupadd

# Disable and remove cockpit
log "Disabling and removing cockpit..."
systemctl stop cockpit.socket cockpit.service 2>/dev/null || true
systemctl disable cockpit.socket cockpit.service 2>/dev/null || true
dnf remove -y cockpit cockpit-ws cockpit-bridge cockpit-system 2>/dev/null || \
    yum remove -y cockpit cockpit-ws cockpit-bridge cockpit-system 2>/dev/null || true

# Disable and remove firewalld (iptables only)
log "Disabling and removing firewalld..."
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true
dnf remove -y firewalld 2>/dev/null || yum remove -y firewalld 2>/dev/null || true

# ============================================================================
# PHASE 6: IPTABLES FIREWALL
# ============================================================================
phase "PHASE 6: IPTABLES FIREWALL"
log "Configuring strict iptables firewall..."

# Install iptables services
dnf install -y iptables-services 2>/dev/null || yum install -y iptables-services 2>/dev/null || true

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Default policies (safety net behind explicit REJECT rules)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP (all - required by competition rules)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Anti-reconnaissance: Bad TCP flags
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -f -j DROP

# Drop invalid state packets (malformed/scan artifacts)
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# SYN rate limiting (slow down port scans - 25 new connections/sec per source IP)
iptables -A INPUT -p tcp --syn -m hashlimit \
    --hashlimit-above 25/sec --hashlimit-burst 50 \
    --hashlimit-mode srcip --hashlimit-name syn_scan \
    --hashlimit-htable-expire 30000 -j DROP

# --- Outbound: DNS, HTTP, HTTPS (for updates/tooling) ---
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# --- Inbound: Splunk services ---
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT   # Splunk Web
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT   # Splunk Forwarders
iptables -A INPUT -p tcp --dport 514 -j ACCEPT    # Syslog (NGFW)
iptables -A INPUT -p tcp --dport 5140 -j ACCEPT   # Technitium DNS Syslog

# --- Inbound: Wazuh ---
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT   # Wazuh Event
iptables -A INPUT -p tcp --dport 1515 -j ACCEPT   # Wazuh Auth
iptables -A INPUT -p tcp --dport 55000 -j ACCEPT  # Wazuh API

# --- Inbound: Salt ---
iptables -A INPUT -p tcp --dport 4505 -j ACCEPT   # Salt Publish
iptables -A INPUT -p tcp --dport 4506 -j ACCEPT   # Salt Request
iptables -A INPUT -p tcp --dport 8001 -j ACCEPT   # Salt API
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT   # Salt Custom GUI

# --- Inbound: DNS (Technitium) ---
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 5380 -j ACCEPT   # Technitium Web UI

# --- Logging for all dropped/rejected packets ---
iptables -A INPUT -j LOG --log-prefix "IPT-INPUT-REJECT: " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "IPT-OUTPUT-REJECT: " --log-level 4
iptables -A FORWARD -j LOG --log-prefix "IPT-FORWARD-REJECT: " --log-level 4

# --- Default REJECT ---
iptables -A INPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable

# Suppress iptables log messages from console (send to /var/log/iptables.log only)
log "Configuring iptables logging to file only (not console)..."
cat > /etc/rsyslog.d/10-iptables.conf << 'RSYSLOG_EOF'
:msg, startswith, "IPT-" /var/log/iptables.log
& stop
RSYSLOG_EOF
systemctl restart rsyslog 2>/dev/null || true
# Set kernel console log level to suppress warnings from terminal
dmesg -n 1 2>/dev/null || true

# Save rules
log "Saving iptables rules..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
/usr/libexec/iptables/iptables.init save 2>/dev/null || true
systemctl enable iptables 2>/dev/null || true
systemctl start iptables 2>/dev/null || true

log "Firewall configured: Splunk(8000,9997,514,5140), Wazuh(1514,1515,55000), Salt(4505,4506,8881,3000), DNS(53,5380)"

# ============================================================================
# PHASE 7: KERNEL HARDENING
# ============================================================================
phase "PHASE 7: KERNEL HARDENING"
log "Applying sysctl kernel hardening..."

SYSCTL_HARDEN="/etc/sysctl.d/99-security-hardening.conf"
[[ -f "$SYSCTL_HARDEN" ]] && cp "$SYSCTL_HARDEN" "${SYSCTL_HARDEN}.backup"
cat > "$SYSCTL_HARDEN" << 'SYSCTL_EOF'
# Kernel Hardening
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
vm.mmap_min_addr = 65536
SYSCTL_EOF
sysctl -p "$SYSCTL_HARDEN" >/dev/null 2>&1 || true
log "Kernel hardening applied"

# PAM audit (non-destructive, read-only)
if [[ -f "$LINUXDEV/pamManager.sh" ]]; then
    log "Running PAM audit (read-only)..."
    bash "$LINUXDEV/pamManager.sh" audit -q 2>&1 | tee -a "$LOG_FILE" || true
fi

# ============================================================================
# PHASE 8: SYSTEM BACKUPS
# ============================================================================
phase "PHASE 8: SYSTEM BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"

# Splunk-specific post-hardening backup
log "Backing up hardened Splunk configuration..."
SPLUNK_BACKUP="/root/splunk_backup_$TIMESTAMP"
if [[ -d "$SPLUNK_HOME" ]]; then
    mkdir -p "$SPLUNK_BACKUP"
    cp -a "$SPLUNK_HOME/etc" "$SPLUNK_BACKUP/"
    log "Splunk config backed up to $SPLUNK_BACKUP"
fi

# ============================================================================
# PHASE 9: SYSTEM BASELINE
# ============================================================================
phase "PHASE 9: SYSTEM BASELINE"
log "Creating post-hardening system baseline..."
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
# PHASE 10: POST-HARDENING ENUMERATION
# ============================================================================
phase "PHASE 10: POST-HARDENING ENUMERATION"

if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    bash "$LINUXDEV/masterEnum.sh" 2>&1 | tee "$LOG_DIR/enum_post_$TIMESTAMP.log"
fi

# ============================================================================
# CLEANUP
# ============================================================================
rm -f "$SPLUNK_PKG"

# ============================================================================
# SUMMARY
# ============================================================================
phase "HARDENING COMPLETE"
echo ""
echo "========================================================"
echo "  SPLUNK/SIEM SERVER HARDENING COMPLETE"
echo "========================================================"
echo ""
echo "Logs: $LOG_DIR/"
echo "Splunk backup (original): $BACKUP_DIR/splunkORIGINAL"
echo "Splunk backup (hardened): $SPLUNK_BACKUP"
echo ""
echo "This box hosts:"
echo "  - Splunk $SPLUNK_VERSION (fresh install)"
if [[ -n "$DASHBOARD_COUNT" ]] && [[ "$DASHBOARD_COUNT" -gt 0 ]]; then
    echo "  - Splunk Dashboards: $DASHBOARD_COUNT SOC dashboards installed"
fi
echo "  - SaltGUI (management)"
echo "  - Wazuh Server (SIEM)"
echo "  - Technitium DNS Server"
echo ""
echo "NEXT STEPS:"
echo "  1. Verify Splunk is accessible: https://localhost:8000"
if [[ -n "$DASHBOARD_COUNT" ]] && [[ "$DASHBOARD_COUNT" -gt 0 ]]; then
    echo "  2. Check dashboards in Splunk Web UI"
    echo "  3. Configure Technitium DNS syslog (Settings > Logging > TCP 127.0.0.1:5140)"
    echo "  4. Install Salt master: saltServerInstall.sh"
    echo "  5. Install Wazuh server"
    echo "  6. Run threat hunting tools carefully"
else
    echo "  2. Import dashboards manually (see linux/securityInfrastructure/Splunk/Dashboards/)"
    echo "  3. Configure Technitium DNS syslog (Settings > Logging > TCP 127.0.0.1:5140)"
    echo "  4. Install Salt master: saltServerInstall.sh"
    echo "  5. Install Wazuh server"
    echo "  6. Run threat hunting tools carefully"
fi
echo ""
echo "SERVICE VERIFICATION:"
echo "  /opt/splunk/bin/splunk status"
echo "  curl -k https://localhost:8000"
echo ""
echo "========================================================"

exit 0
