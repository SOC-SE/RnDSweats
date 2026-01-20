#!/bin/bash
# ==============================================================================
# Quick Harden - Linux
# Fast security hardening for competition
# USE WITH CAUTION - Makes system changes!
# ==============================================================================

set -e

echo "========================================"
echo "QUICK HARDEN - $(hostname)"
echo "Time: $(date)"
echo "========================================"

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: Must run as root"
   exit 1
fi

echo -e "\n[1/10] SECURING SSH"
echo "----------------------------------------"
SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]]; then
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
    echo "SSH config hardened"
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

echo -e "\n[2/10] LOCKING ROOT ACCOUNT (SSH)"
echo "----------------------------------------"
passwd -l root 2>/dev/null && echo "Root account locked" || echo "Could not lock root"

echo -e "\n[3/10] SECURING FILE PERMISSIONS"
echo "----------------------------------------"
chmod 600 /etc/shadow 2>/dev/null && echo "shadow: 600"
chmod 644 /etc/passwd 2>/dev/null && echo "passwd: 644"
chmod 600 /etc/gshadow 2>/dev/null && echo "gshadow: 600"
chmod 644 /etc/group 2>/dev/null && echo "group: 644"

echo -e "\n[4/10] REMOVING UNAUTHORIZED SUID BITS"
echo "----------------------------------------"
# Only remove from non-standard locations
find /home /tmp /var/tmp -perm -4000 -exec chmod u-s {} \; 2>/dev/null && echo "SUID bits removed from user dirs"

echo -e "\n[5/10] CLEARING TEMP DIRECTORIES"
echo "----------------------------------------"
find /tmp -type f -atime +1 -delete 2>/dev/null
find /var/tmp -type f -atime +1 -delete 2>/dev/null
rm -rf /dev/shm/* 2>/dev/null
echo "Temp directories cleaned"

echo -e "\n[6/10] DISABLING UNNECESSARY SERVICES"
echo "----------------------------------------"
for svc in telnet rsh rlogin rexec finger; do
    systemctl stop "$svc" 2>/dev/null && systemctl disable "$svc" 2>/dev/null && echo "Disabled: $svc"
done

echo -e "\n[7/10] SETTING SECURE UMASK"
echo "----------------------------------------"
echo "umask 027" >> /etc/profile
echo "Umask set to 027"

echo -e "\n[8/10] ENABLING FIREWALL (Basic Rules)"
echo "----------------------------------------"
if command -v ufw &>/dev/null; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw allow 4505/tcp comment 'Salt Publish'
    ufw allow 4506/tcp comment 'Salt Return'
    ufw --force enable
    echo "UFW enabled with basic rules"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --set-default-zone=drop
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-port=4505/tcp
    firewall-cmd --permanent --add-port=4506/tcp
    firewall-cmd --reload
    echo "firewalld configured"
else
    # Fallback to iptables
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 4505 -j ACCEPT
    iptables -A INPUT -p tcp --dport 4506 -j ACCEPT
    echo "iptables basic rules applied"
fi

echo -e "\n[9/10] SECURING CRON"
echo "----------------------------------------"
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null
echo "Cron directories secured"

echo -e "\n[10/10] CHECKING FOR UNAUTHORIZED USERS"
echo "----------------------------------------"
# List users with UID 0 (should only be root)
awk -F: '$3==0 {print "UID 0 user: "$1}' /etc/passwd
# List users with login shells
echo "Users with login shells:"
grep -E "/bin/(bash|sh|zsh|ksh|csh)$" /etc/passwd | cut -d: -f1 | tr '\n' ' '
echo ""

echo -e "\n========================================"
echo "QUICK HARDEN COMPLETE"
echo "Review output and test services!"
echo "========================================"
