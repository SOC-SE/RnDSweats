#!/bin/bash
# ==============================================================================
# Service Monitor - Linux
# Check if critical services are running and report status
# For Salt-GUI / CCDC Competition Use - Scoring Engine Checks
#
# By Samuel Brucker 2025-2026
# ==============================================================================

set -euo pipefail

# Define critical services to monitor (customize per competition)
# Format: service_name:friendly_name:port
SERVICES=(
    "sshd:SSH:22"
    "apache2:Apache:80"
    "nginx:Nginx:80"
    "httpd:Apache:80"
    "mysql:MySQL:3306"
    "mariadb:MariaDB:3306"
    "postgresql:PostgreSQL:5432"
    "named:DNS:53"
    "bind9:DNS:53"
    "dovecot:IMAP:143"
    "postfix:SMTP:25"
    "vsftpd:FTP:21"
    "proftpd:FTP:21"
    "samba:SMB:445"
    "smbd:SMB:445"
)

echo "========================================"
echo "SERVICE MONITOR - $(hostname)"
echo "Time: $(date)"
echo "========================================"

overall_status=0

check_service() {
    local svc_name="$1"
    local friendly="$2"
    local port="$3"

    # Check if service is running
    if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
        svc_status="RUNNING"
        svc_color="\033[0;32m"  # Green
    elif pgrep -x "$svc_name" >/dev/null 2>&1; then
        svc_status="RUNNING"
        svc_color="\033[0;32m"
    else
        svc_status="STOPPED"
        svc_color="\033[0;31m"  # Red
        overall_status=1
    fi

    # Check if port is listening
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        port_status="LISTENING"
        port_color="\033[0;32m"
    elif netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        port_status="LISTENING"
        port_color="\033[0;32m"
    else
        port_status="CLOSED"
        port_color="\033[0;31m"
        overall_status=1
    fi

    printf "%-20s %-15s ${svc_color}%-10s\033[0m ${port_color}%-10s\033[0m\n" \
        "$friendly" "($svc_name)" "$svc_status" "Port $port: $port_status"
}

echo -e "\nService              Name            Status     Port"
echo "--------------------------------------------------------------"

for entry in "${SERVICES[@]}"; do
    svc_name=$(echo "$entry" | cut -d: -f1)
    friendly=$(echo "$entry" | cut -d: -f2)
    port=$(echo "$entry" | cut -d: -f3)

    # Only check if service exists on this system
    if systemctl list-unit-files "$svc_name.service" &>/dev/null 2>&1 || \
       command -v "$svc_name" &>/dev/null || \
       [ -f "/etc/init.d/$svc_name" ]; then
        check_service "$svc_name" "$friendly" "$port"
    fi
done

echo ""
echo "========================================"
if [ $overall_status -eq 0 ]; then
    echo -e "\033[0;32mALL MONITORED SERVICES OK\033[0m"
else
    echo -e "\033[0;31mSOME SERVICES NEED ATTENTION\033[0m"
fi
echo "========================================"

exit $overall_status
