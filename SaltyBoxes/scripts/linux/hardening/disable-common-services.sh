#!/bin/bash
# Disable commonly exploited services that are not typically needed

SERVICES=(
    "cups"           # Printing - rarely needed on servers
    "avahi-daemon"   # mDNS/Bonjour - rarely needed
    "bluetooth"      # Bluetooth - server doesn't need it
    "rpcbind"        # RPC - NFS dependency, disable if not using
    "nfs-server"     # NFS - disable unless explicitly needed
)

echo "=== Disabling Common Services ==="
for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null && echo "Stopped: $svc" || echo "Failed to stop: $svc"
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc" 2>/dev/null && echo "Disabled: $svc" || echo "Failed to disable: $svc"
    fi
done

echo ""
echo "=== Service Hardening Complete ==="
