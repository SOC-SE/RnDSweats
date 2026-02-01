#!/bin/bash
# ==============================================================================
# Forensic Artifact Collection - Linux
# Collect key artifacts before remediation
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

set -euo pipefail

ARTIFACT_DIR="/tmp/artifacts_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ARTIFACT_DIR"

echo "========================================"
echo "ARTIFACT COLLECTION - $(hostname)"
echo "Time: $(date)"
echo "Output: $ARTIFACT_DIR"
echo "========================================"

echo -e "\n[1/10] PROCESS LISTING"
echo "----------------------------------------"
ps auxwww > "$ARTIFACT_DIR/ps_aux.txt" 2>&1
ps -eo pid,ppid,user,args --forest > "$ARTIFACT_DIR/ps_tree.txt" 2>&1
echo "Saved process listings"

echo -e "\n[2/10] NETWORK STATE"
echo "----------------------------------------"
ss -tulnpa > "$ARTIFACT_DIR/ss_all.txt" 2>&1
ss -tnp state established > "$ARTIFACT_DIR/ss_established.txt" 2>&1
cat /proc/net/tcp /proc/net/tcp6 > "$ARTIFACT_DIR/proc_net_tcp.txt" 2>&1
ip addr > "$ARTIFACT_DIR/ip_addr.txt" 2>&1
ip route > "$ARTIFACT_DIR/ip_route.txt" 2>&1
arp -a > "$ARTIFACT_DIR/arp.txt" 2>&1
echo "Saved network state"

echo -e "\n[3/10] USER INFORMATION"
echo "----------------------------------------"
cp /etc/passwd "$ARTIFACT_DIR/passwd" 2>/dev/null || true
cp /etc/shadow "$ARTIFACT_DIR/shadow" 2>/dev/null || true
cp /etc/group "$ARTIFACT_DIR/group" 2>/dev/null || true
last -50 > "$ARTIFACT_DIR/last.txt" 2>&1
lastb -50 > "$ARTIFACT_DIR/lastb.txt" 2>&1 || true
who > "$ARTIFACT_DIR/who.txt" 2>&1
w > "$ARTIFACT_DIR/w.txt" 2>&1
echo "Saved user information"

echo -e "\n[4/10] CRON JOBS"
echo "----------------------------------------"
mkdir -p "$ARTIFACT_DIR/cron"
cp -r /etc/cron* "$ARTIFACT_DIR/cron/" 2>/dev/null || true
cp -r /var/spool/cron "$ARTIFACT_DIR/cron/spool" 2>/dev/null || true
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" > "$ARTIFACT_DIR/cron/crontab_$user.txt" 2>/dev/null || true
done
echo "Saved cron jobs"

echo -e "\n[5/10] STARTUP AND SERVICES"
echo "----------------------------------------"
systemctl list-units --type=service --all > "$ARTIFACT_DIR/systemd_services.txt" 2>&1
systemctl list-unit-files > "$ARTIFACT_DIR/systemd_unit_files.txt" 2>&1
ls -la /etc/init.d/ > "$ARTIFACT_DIR/initd.txt" 2>&1
cat /etc/rc.local > "$ARTIFACT_DIR/rc_local.txt" 2>/dev/null || true
echo "Saved service information"

echo -e "\n[6/10] LOADED KERNEL MODULES"
echo "----------------------------------------"
lsmod > "$ARTIFACT_DIR/lsmod.txt" 2>&1
cat /proc/modules > "$ARTIFACT_DIR/proc_modules.txt" 2>&1
echo "Saved kernel modules"

echo -e "\n[7/10] SSH KEYS"
echo "----------------------------------------"
mkdir -p "$ARTIFACT_DIR/ssh_keys"
find /home /root -name "authorized_keys" -exec cp {} "$ARTIFACT_DIR/ssh_keys/" \; 2>/dev/null || true
find /home /root -name "known_hosts" -exec cp {} "$ARTIFACT_DIR/ssh_keys/" \; 2>/dev/null || true
echo "Saved SSH keys"

echo -e "\n[8/10] RECENT FILES"
echo "----------------------------------------"
find / -type f -mmin -60 2>/dev/null | grep -vE "(/proc/|/sys/|/run/)" > "$ARTIFACT_DIR/files_modified_1hr.txt" || true
find /tmp /var/tmp /dev/shm -type f 2>/dev/null > "$ARTIFACT_DIR/temp_files.txt" || true
echo "Saved recent file listings"

echo -e "\n[9/10] PROCESS MEMORY MAPS (for suspicious PIDs)"
echo "----------------------------------------"
mkdir -p "$ARTIFACT_DIR/proc_maps"
# Get PIDs of processes running from /tmp or deleted binaries
for pid in $(ls -la /proc/*/exe 2>/dev/null | grep -E "(/tmp/|deleted)" | grep -oP '/proc/\K[0-9]+'); do
    cat "/proc/$pid/maps" > "$ARTIFACT_DIR/proc_maps/pid_$pid.txt" 2>/dev/null || true
    cat "/proc/$pid/cmdline" > "$ARTIFACT_DIR/proc_maps/cmdline_$pid.txt" 2>/dev/null || true
done
echo "Saved suspicious process maps"

echo -e "\n[10/10] LOG SNAPSHOTS"
echo "----------------------------------------"
mkdir -p "$ARTIFACT_DIR/logs"
tail -1000 /var/log/auth.log > "$ARTIFACT_DIR/logs/auth.log" 2>/dev/null || \
tail -1000 /var/log/secure > "$ARTIFACT_DIR/logs/secure.log" 2>/dev/null || true
tail -1000 /var/log/syslog > "$ARTIFACT_DIR/logs/syslog" 2>/dev/null || \
tail -1000 /var/log/messages > "$ARTIFACT_DIR/logs/messages" 2>/dev/null || true
dmesg > "$ARTIFACT_DIR/logs/dmesg.txt" 2>&1
journalctl -n 1000 --no-pager > "$ARTIFACT_DIR/logs/journal.txt" 2>&1 || true
echo "Saved log snapshots"

echo -e "\n========================================"
echo "ARTIFACT COLLECTION COMPLETE"
echo "Artifacts saved to: $ARTIFACT_DIR"
echo "========================================"

# Create tarball
tar -czf "${ARTIFACT_DIR}.tar.gz" -C "$(dirname $ARTIFACT_DIR)" "$(basename $ARTIFACT_DIR)" 2>/dev/null
echo "Tarball created: ${ARTIFACT_DIR}.tar.gz"
