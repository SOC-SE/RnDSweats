#!/bin/bash
# ==============================================================================
# Persistence Hunter - Linux
# Comprehensive check for attacker persistence mechanisms
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

set -euo pipefail

echo "========================================"
echo "PERSISTENCE HUNTER - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/15] CRON JOBS - All Users"
echo "----------------------------------------"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null && echo "  ^ Crontab for: $user"
done
[ $? -ne 0 ] && echo "No user crontabs found"

echo -e "\n[2/15] SYSTEM CRON DIRECTORIES"
echo "----------------------------------------"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$dir" ]; then
        echo "=== $dir ==="
        ls -la "$dir" 2>/dev/null | grep -v "^total"
    fi
done

echo -e "\n[3/15] /etc/crontab"
echo "----------------------------------------"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "crontab not found"

echo -e "\n[4/15] SYSTEMD USER SERVICES"
echo "----------------------------------------"
echo "=== System services modified recently ==="
find /etc/systemd/system -type f -name "*.service" -mtime -7 2>/dev/null || echo "None"
echo ""
echo "=== User systemd services ==="
find /home -path "*/.config/systemd/user/*.service" 2>/dev/null || echo "None"

echo -e "\n[5/15] SUSPICIOUS SYSTEMD SERVICES (Non-standard)"
echo "----------------------------------------"
if command -v systemctl &>/dev/null; then
    known_services="systemd|dbus|NetworkManager|sshd|rsyslog|cron|crond|salt|auditd|firewalld|chronyd"
    systemctl list-unit-files --type=service 2>/dev/null | grep enabled | grep -vE "^($known_services)" | head -30 || echo "None found"
else
    echo "systemctl not available"
fi

echo -e "\n[6/15] INIT.D SCRIPTS"
echo "----------------------------------------"
ls -la /etc/init.d/ 2>/dev/null | grep -v "^total" || echo "No init.d scripts"

echo -e "\n[7/15] RC.LOCAL"
echo "----------------------------------------"
for rc in /etc/rc.local /etc/rc.d/rc.local; do
    if [ -f "$rc" ]; then
        echo "=== $rc ==="
        cat "$rc" 2>/dev/null | grep -v "^#" | grep -v "^$"
    fi
done

echo -e "\n[8/15] AUTHORIZED_KEYS - All Users"
echo "----------------------------------------"
find /home -name "authorized_keys" 2>/dev/null -exec echo "File: {}" \; -exec cat {} \;
if [ -f /root/.ssh/authorized_keys ]; then
    echo "File: /root/.ssh/authorized_keys"
    cat /root/.ssh/authorized_keys
fi

echo -e "\n[9/15] SUID/SGID BINARIES (Non-standard paths)"
echo "----------------------------------------"
find / -perm -4000 -o -perm -2000 2>/dev/null | grep -vE "^/(usr|bin|sbin)" | head -20 || echo "None found"

echo -e "\n[10/15] WORLD-WRITABLE FILES IN SYSTEM DIRS"
echo "----------------------------------------"
find /etc /usr /bin /sbin -type f -perm -002 2>/dev/null | head -20 || echo "None found"

echo -e "\n[11/15] HIDDEN FILES IN /TMP AND /VAR/TMP"
echo "----------------------------------------"
find /tmp /var/tmp -name ".*" -type f 2>/dev/null || echo "None found"
echo ""
echo "=== /dev/shm contents ==="
ls -la /dev/shm/ 2>/dev/null | grep -v "^total" || echo "Empty"

echo -e "\n[12/15] KERNEL MODULES"
echo "----------------------------------------"
lsmod 2>/dev/null | grep -vE "^(Module|ext4|xfs|nfs|overlay|bridge|ip_tables|nf_|xt_|x_tables|nfnetlink)" || echo "Unable to list modules"

echo -e "\n[13/15] SHELL PROFILES (Backdoor injection)"
echo "----------------------------------------"
profiles="/etc/profile /etc/bash.bashrc /etc/bashrc"
for p in $profiles; do
    if [ -f "$p" ]; then
        if grep -lE "nc |ncat|bash -i|/dev/tcp|curl|wget" "$p" 2>/dev/null; then
            echo "SUSPICIOUS: $p"
        fi
    fi
done

# Check user profiles
find /home /root -maxdepth 2 -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" 2>/dev/null | while read -r profile; do
    if grep -lE "nc |ncat|bash -i|/dev/tcp|curl.*\|.*sh|wget.*\|.*sh" "$profile" 2>/dev/null; then
        echo "SUSPICIOUS: $profile"
    fi
done
echo "Check complete"

echo -e "\n[14/15] LD_PRELOAD HIJACKING"
echo "----------------------------------------"
echo "=== /etc/ld.so.preload ==="
cat /etc/ld.so.preload 2>/dev/null || echo "File not found (good)"
echo ""
echo "=== LD_PRELOAD in environment ==="
env | grep LD_PRELOAD || echo "Not set (good)"

echo -e "\n[15/15] AT JOBS"
echo "----------------------------------------"
if command -v atq &>/dev/null; then
    atq 2>/dev/null || echo "No at jobs"
else
    echo "at not installed"
fi

echo -e "\n========================================"
echo "PERSISTENCE HUNT COMPLETE"
echo "========================================"
