#!/bin/bash
# Gather basic system information for inventory purposes

echo "=== System Information ==="
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo ""
echo "=== Network ==="
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1'
echo ""
echo "=== Users with Shell Access ==="
grep -E '/bin/(bash|sh|zsh)$' /etc/passwd | cut -d: -f1
echo ""
echo "=== Listening Ports ==="
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u
