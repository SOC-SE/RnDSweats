#!/bin/bash
# ==========================================
# FIREJAIL EMERGENCY ROLLBACK SCRIPT
# ==========================================

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root."
  exit 1
fi

echo "Stopping Firejail sandboxes..."

# Find all systemd overrides created by our scanner
# They are located in /etc/systemd/system/*.service.d/firejail.conf

files=$(find /etc/systemd/system/ -name "firejail.conf")

if [ -z "$files" ]; then
    echo "No Firejail overrides found. You are clean!"
    exit 0
fi

for file in $files; do
    # 1. Extract the directory name to guess the service name
    dir_path=$(dirname "$file")     # e.g., /etc/systemd/system/nginx.service.d
    dir_name=$(basename "$dir_path") # e.g., nginx.service.d
    service_name=${dir_name%.d}      # e.g., nginx.service

    echo "Reverting $service_name..."

    # 2. Delete the override file
    rm -f "$file"

    # 3. Remove the directory if it's empty now
    rmdir "$dir_path" 2>/dev/null || true
    
    # 4. Add to list for restarting
    services_to_restart+=("$service_name")
done

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Restarting reverted services..."
for service in "${services_to_restart[@]}"; do
    echo "Restarting $service..."
    systemctl restart "$service"
done

echo "Rollback Complete. Firejail systemd integration has been removed."