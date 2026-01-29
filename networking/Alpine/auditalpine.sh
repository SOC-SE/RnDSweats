#!/bin/sh

OUTPUT_FILE="audit_report.txt"

{
echo "=================================================="
echo "SYSTEM AUDIT REPORT - ALPINE LINUX"
date
echo "=================================================="

echo ""
echo "[+] HOSTNAME"
echo "--------------------------------------------------"
hostname

echo ""
echo "[+] OS VERSION"
echo "--------------------------------------------------"
cat /etc/alpine-release 2>/dev/null

echo ""
echo "[+] IP ADDRESS INFO"
echo "--------------------------------------------------"
ip addr show

echo ""
echo "[+] LISTENING PORTS"
echo "--------------------------------------------------"
netstat -tuln

echo ""
echo "[+] MOUNTED DRIVES"
echo "--------------------------------------------------"
mount

echo ""
echo "[+] CRON JOBS (System & User)"
echo "--------------------------------------------------"
echo "--- System Periodic Jobs (run-parts) ---"
for dir in /etc/periodic/*; do
    if [ -d "$dir" ]; then
        echo "Period: $(basename "$dir")"
        ls -1 "$dir" 2>/dev/null | sed 's/^/  - /'
    fi
done

echo ""
echo "--- User Crontabs (Active Lines Only) ---"
for cronfile in /etc/crontabs/*; do
    if [ -f "$cronfile" ]; then
        echo "User: $(basename "$cronfile")"
        grep -vE '^#|^$' "$cronfile" | sed 's/^/  > /'
    fi
done

echo ""
echo "[+] CONTAINER ENUMERATION"
echo "--------------------------------------------------"
if command -v docker >/dev/null 2>&1; then
    echo "--- Docker Containers ---"
    docker ps -a
else
    echo "Docker not found."
fi

if command -v kubectl >/dev/null 2>&1; then
    echo "--- Kubernetes Resources ---"
    kubectl get pods --all-namespaces
else
    echo "Kubernetes (kubectl) not found."
fi

echo ""
echo "[+] HUMAN USERS (UID >= 1000 or Root)"
echo "--------------------------------------------------"
awk -F: '($3 >= 1000 || $3 == 0) && $7 !~ /nologin|false/ {print "User: " $1 " | UID: " $3 " | Shell: " $7}' /etc/passwd

echo ""
echo "[+] USER GROUPS AND PERMISSIONS"
echo "--------------------------------------------------"
for user in $(awk -F: '($3 >= 1000 || $3 == 0) && $7 !~ /nologin|false/ {print $1}' /etc/passwd); do
    id "$user"
done

echo ""
echo "[+] ADMIN/SUDO USERS AND GROUPS"
echo "--------------------------------------------------"
grep '^wheel:' /etc/group
echo "--- Sudoers Configuration ---"
grep -vE '^#|^$' /etc/sudoers 2>/dev/null

echo ""
echo "[+] USERS WITHOUT PASSWORDS (Empty Shadow Hash)"
echo "--------------------------------------------------"
awk -F: '($2 == "" ) { print $1 }' /etc/shadow 2>/dev/null

echo ""
echo "[+] SSH POLICY CONFIGURATION"
echo "--------------------------------------------------"
grep -vE '^#|^$' /etc/ssh/sshd_config 2>/dev/null

} > "$OUTPUT_FILE" 2>&1

echo "Enumeration complete. Results saved to $OUTPUT_FILE"