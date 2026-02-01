#!/bin/bash
# Hunt for common persistence mechanisms that attackers use

echo "=== Persistence Hunt ==="
echo ""

echo "=== Cron Jobs (All Users) ==="
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "  (user: $user)"
done

echo ""
echo "=== System Cron Directories ==="
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.daily/ 2>/dev/null
ls -la /etc/cron.hourly/ 2>/dev/null

echo ""
echo "=== Systemd User Services ==="
find /etc/systemd/system -name "*.service" -type f 2>/dev/null

echo ""
echo "=== Authorized SSH Keys ==="
find /home -name "authorized_keys" -type f 2>/dev/null -exec echo "File: {}" \; -exec cat {} \;
find /root -name "authorized_keys" -type f 2>/dev/null -exec echo "File: {}" \; -exec cat {} \;

echo ""
echo "=== SUID/SGID Binaries ==="
find / -perm /6000 -type f 2>/dev/null | head -20

echo ""
echo "=== Suspicious Bash Profiles ==="
grep -l "nc\|ncat\|bash -i\|python.*socket\|perl.*socket" /home/*/.bashrc /home/*/.profile /root/.bashrc /root/.profile 2>/dev/null

echo ""
echo "=== Hunt Complete ==="
