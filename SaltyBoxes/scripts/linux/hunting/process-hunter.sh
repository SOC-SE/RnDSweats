#!/bin/bash
# ==============================================================================
# Process Hunter - Linux
# Find suspicious processes and malware
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

set -euo pipefail

echo "========================================"
echo "PROCESS HUNTER - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/12] PROCESSES RUNNING AS ROOT"
echo "----------------------------------------"
ps aux 2>/dev/null | awk '$1=="root" {print}' | grep -vE "(ps aux|sshd|systemd|salt|cron|rsyslog|agetty)" | head -30 || echo "None found"

echo -e "\n[2/12] PROCESSES WITH NO TTY (Potential Backdoors)"
echo "----------------------------------------"
ps aux 2>/dev/null | awk '$7=="?" {print}' | grep -vE "(systemd|kworker|migration|ksoftirq|kdevtmp|salt|rcu|scsi|ata_)" | head -30 || echo "None found"

echo -e "\n[3/12] HIGH CPU PROCESSES (Top 15)"
echo "----------------------------------------"
ps aux --sort=-%cpu 2>/dev/null | head -16 || echo "Unable to list"

echo -e "\n[4/12] HIGH MEMORY PROCESSES (Top 15)"
echo "----------------------------------------"
ps aux --sort=-%mem 2>/dev/null | head -16 || echo "Unable to list"

echo -e "\n[5/12] SUSPICIOUS PROCESS NAMES"
echo "----------------------------------------"
suspicious="nc |ncat|netcat|cryptominer|xmrig|minerd|kinsing|kdevtmpfsi|\.tmp|/tmp/|/dev/shm|mimikatz|lazagne|linpeas|pspy"
matches=$(ps aux 2>/dev/null | grep -iE "$suspicious" | grep -v grep)
if [ -n "$matches" ]; then
    echo "$matches"
else
    echo "None found"
fi

echo -e "\n[6/12] PROCESSES SPAWNED FROM /TMP OR /DEV/SHM"
echo "----------------------------------------"
ls -la /proc/*/exe 2>/dev/null | grep -E "(/tmp/|/dev/shm/|deleted)" | head -20 || echo "None found"

echo -e "\n[7/12] PROCESSES WITH DELETED EXECUTABLES"
echo "----------------------------------------"
deleted=$(ls -la /proc/*/exe 2>/dev/null | grep deleted)
if [ -n "$deleted" ]; then
    echo "$deleted"
else
    echo "None found"
fi

echo -e "\n[8/12] PROCESS TREE (Unusual Parents)"
echo "----------------------------------------"
if command -v pstree &>/dev/null; then
    pstree -p 2>/dev/null | grep -vE "(systemd|sshd|salt|bash|sh)" | head -30 || echo "Unable to display"
else
    echo "pstree not available"
fi

echo -e "\n[9/12] RECENTLY STARTED PROCESSES"
echo "----------------------------------------"
ps -eo pid,user,lstart,cmd --sort=-start_time 2>/dev/null | head -20 || echo "Unable to list"

echo -e "\n[10/12] PROCESSES LISTENING ON NETWORK"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tulnp 2>/dev/null | grep -v "^Netid" | awk '{print $7}' | sort -u | while read -r proc; do
        if [ -n "$proc" ]; then
            echo "$proc"
        fi
    done
else
    netstat -tulnp 2>/dev/null | grep LISTEN | awk '{print $7}' | sort -u || echo "Unable to list"
fi

echo -e "\n[11/12] PROCESSES WITH NETWORK CONNECTIONS TO EXTERNAL IPs"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tunp 2>/dev/null | grep -vE "127\.0\.0\.1|::1|0\.0\.0\.0" | head -20 || echo "None found"
else
    echo "ss not available"
fi

echo -e "\n[12/12] HIDDEN PROCESSES CHECK"
echo "----------------------------------------"
# Compare /proc entries with ps output
ps_pids=$(ps -eo pid --no-headers | tr -d ' ' | sort -n)
proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n)
hidden=$(comm -13 <(echo "$ps_pids") <(echo "$proc_pids") 2>/dev/null)
if [ -n "$hidden" ]; then
    echo "POTENTIAL HIDDEN PROCESSES:"
    echo "$hidden"
else
    echo "No hidden processes detected"
fi

echo -e "\n========================================"
echo "PROCESS HUNT COMPLETE"
echo "========================================"
