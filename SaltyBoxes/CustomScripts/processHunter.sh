#!/bin/bash
# ==============================================================================
# Process Hunter - Linux
# Find suspicious processes and malware
# ==============================================================================

echo "========================================"
echo "PROCESS HUNTER - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/10] PROCESSES RUNNING AS ROOT"
echo "----------------------------------------"
ps aux | awk '$1=="root" {print}' | grep -vE "(ps aux|sshd|systemd|salt|cron|rsyslog)" | head -30

echo -e "\n[2/10] PROCESSES WITH NO TTY (Potential Backdoors)"
echo "----------------------------------------"
ps aux | awk '$7=="?" {print}' | grep -vE "(systemd|kworker|migration|ksoftirq|kdevtmp|salt)" | head -30

echo -e "\n[3/10] HIGH CPU PROCESSES"
echo "----------------------------------------"
ps aux --sort=-%cpu | head -15

echo -e "\n[4/10] HIGH MEMORY PROCESSES"
echo "----------------------------------------"
ps aux --sort=-%mem | head -15

echo -e "\n[5/10] SUSPICIOUS PROCESS NAMES"
echo "----------------------------------------"
ps aux | grep -iE "(nc |ncat|netcat|cryptominer|xmrig|minerd|kinsing|kdevtmpfsi|\.tmp|/tmp/|/dev/shm)" | grep -v grep || echo "None found"

echo -e "\n[6/10] PROCESSES SPAWNED FROM /TMP OR /DEV/SHM"
echo "----------------------------------------"
ls -la /proc/*/exe 2>/dev/null | grep -E "(/tmp/|/dev/shm/|deleted)" | head -20

echo -e "\n[7/10] PROCESSES WITH DELETED EXECUTABLES"
echo "----------------------------------------"
ls -la /proc/*/exe 2>/dev/null | grep deleted

echo -e "\n[8/10] PROCESS TREE (Unusual Parents)"
echo "----------------------------------------"
pstree -p | grep -vE "(systemd|sshd|salt|bash|sh)" | head -30

echo -e "\n[9/10] RECENTLY STARTED PROCESSES"
echo "----------------------------------------"
ps -eo pid,user,lstart,cmd --sort=-start_time | head -20

echo -e "\n[10/10] PROCESSES LISTENING ON NETWORK"
echo "----------------------------------------"
ss -tulnp | grep -v "^Netid" | awk '{print $7}' | sort -u | while read proc; do
    if [ -n "$proc" ]; then
        echo "$proc"
    fi
done

echo -e "\n========================================"
echo "PROCESS HUNT COMPLETE"
echo "========================================"
