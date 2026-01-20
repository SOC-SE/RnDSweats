#!/bin/bash
# ==============================================================================
# Persistence Hunter - Linux
# Comprehensive check for attacker persistence mechanisms
# For CCDC Competition Use
# ==============================================================================

echo "========================================"
echo "PERSISTENCE HUNTER - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/12] CRON JOBS - All Users"
echo "----------------------------------------"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null && echo "  ^ Crontab for: $user"
done

echo -e "\n[2/12] CRON DIRECTORIES"
echo "----------------------------------------"
ls -la /etc/cron.* 2>/dev/null
cat /etc/crontab 2>/dev/null

echo -e "\n[3/12] SYSTEMD USER SERVICES"
echo "----------------------------------------"
find /etc/systemd/system -type f -name "*.service" -newer /etc/passwd 2>/dev/null
find /home -path "*/.config/systemd/user/*.service" 2>/dev/null
ls -la /etc/systemd/system/*.service 2>/dev/null | head -20

echo -e "\n[4/12] SUSPICIOUS SYSTEMD SERVICES"
echo "----------------------------------------"
systemctl list-unit-files --type=service | grep enabled | grep -vE "^(systemd|dbus|NetworkManager|sshd|rsyslog|cron|salt)" | head -30

echo -e "\n[5/12] INIT.D SCRIPTS"
echo "----------------------------------------"
ls -la /etc/init.d/ 2>/dev/null | grep -v "^total"

echo -e "\n[6/12] RC.LOCAL"
echo "----------------------------------------"
cat /etc/rc.local 2>/dev/null
cat /etc/rc.d/rc.local 2>/dev/null

echo -e "\n[7/12] AUTHORIZED_KEYS - All Users"
echo "----------------------------------------"
find /home -name "authorized_keys" -exec echo "File: {}" \; -exec cat {} \; 2>/dev/null
cat /root/.ssh/authorized_keys 2>/dev/null && echo "  ^ root authorized_keys"

echo -e "\n[8/12] SUID/SGID BINARIES (Unusual)"
echo "----------------------------------------"
find / -perm -4000 -o -perm -2000 2>/dev/null | grep -vE "^/(usr|bin|sbin)" | head -20

echo -e "\n[9/12] WORLD-WRITABLE FILES IN SYSTEM DIRS"
echo "----------------------------------------"
find /etc /usr /bin /sbin -type f -perm -002 2>/dev/null | head -20

echo -e "\n[10/12] HIDDEN FILES IN /TMP AND /VAR/TMP"
echo "----------------------------------------"
find /tmp /var/tmp -name ".*" -type f 2>/dev/null
ls -la /dev/shm/ 2>/dev/null | grep -v "^total"

echo -e "\n[11/12] KERNEL MODULES"
echo "----------------------------------------"
lsmod | grep -vE "^(Module|ext4|xfs|nfs|overlay|bridge|ip_tables|nf_)"

echo -e "\n[12/12] SHELL PROFILES (Backdoors)"
echo "----------------------------------------"
grep -l "nc \|ncat\|bash -i\|/dev/tcp\|curl\|wget" /etc/profile /etc/profile.d/* /etc/bash.bashrc /home/*/.bashrc /home/*/.profile /root/.bashrc /root/.profile 2>/dev/null

echo -e "\n========================================"
echo "PERSISTENCE HUNT COMPLETE"
echo "========================================"
