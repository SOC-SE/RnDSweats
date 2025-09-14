#!/bin/bash

# ====================================================================================
# FireJail Service Scanner and Hardening Script
#
# This script scans for running systemd services that have a corresponding
# FireJail profile and interactively prompts the user to apply the sandbox.
#
# USAGE: sudo ./firejailScanner.sh
# ====================================================================================

# --- Script Configuration ---
set -o pipefail

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Function to Print Messages ---
log_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}--- $1 ---${NC}"
}

# --- Root User Check ---
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root to modify system services. Please use sudo."
  exit 1
fi

# --- Prerequisite Check ---
if ! command -v firejail &> /dev/null; then
    log_warning "FireJail is not installed. Please run 'firejailInstall.sh' first."
    exit 1
fi

# --- Function to Secure a Service ---
secure_service() {
    local service_name="$1"
    local service_file="${service_name}.service"

    log_message "Attempting to secure '$service_name'..."

    # 1. Get the original ExecStart command path and arguments
    local original_exec_start
    original_exec_start=$(systemctl show -p ExecStart --value "$service_file")

    if [ -z "$original_exec_start" ]; then
        log_warning "Could not determine the ExecStart command for '$service_name'. Cannot automate. Skipping."
        return 1
    fi

    # The value is a struct; we just need the command and its args
    # The first element is the path, the rest are args.
    local exec_command_line
    exec_command_line=$(echo "$original_exec_start" | sed -e "s/^{ path=\([^;]*\); args=\[\([^]]*\)\]; .*}/\1 \2/" -e 's/"//g' -e 's/;/ /g')

    # 2. Create the systemd override directory
    local override_dir="/etc/systemd/system/${service_file}.d"
    mkdir -p "$override_dir"

    # 3. Create the override.conf file
    local override_file="${override_dir}/firejail.conf"
    log_message "Creating systemd override at $override_file"

    local firejail_path
    firejail_path=$(command -v firejail)

    # The ExecStart= is crucial to clear the original command before adding the new one.
    cat > "$override_file" <<EOF
[Service]
ExecStart=
ExecStart=${firejail_path} ${exec_command_line}
EOF

    # 4. Reload systemd and restart the service
    log_message "Reloading systemd daemon and restarting '$service_name'..."
    systemctl daemon-reload
    systemctl restart "$service_name"

    # 5. Verify the sandbox
    sleep 2 # Give the service a moment to start
    if systemctl is-active --quiet "$service_name" && firejail --list | grep -q -E "(${service_name}|$(basename "$exec_command_line"))"; then
        log_message "✅ '$service_name' is now running inside a FireJail sandbox."
    elif systemctl is-active --quiet "$service_name"; then
        log_warning "⚠️ '$service_name' restarted, but could not be found in 'firejail --list'. Please verify manually."
    else
        log_warning "❌ '$service_name' failed to restart after applying the sandbox. Check 'systemctl status $service_name'."
        log_warning "To revert, remove the override file: 'rm -f $override_file', then run 'systemctl daemon-reload' and 'systemctl restart $service_name'."
    fi
}

# --- Main Execution ---

log_step "Step 1: Scanning for Securable Services"

PROFILE_DIR="/etc/firejail"

# Get a list of running systemd services
mapfile -t running_services < <(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')

securable_services=()

log_message "Found ${#running_services[@]} running services. Checking for available FireJail profiles..."

for service in "${running_services[@]}"; do
    # Strip the .service suffix to get the base name
    base_name=${service%.service}

    # Check if a corresponding .profile exists
    if [ -f "${PROFILE_DIR}/${base_name}.profile" ]; then
        # Check if it's already sandboxed by checking for our override file
        if [ -f "/etc/systemd/system/${service}.d/firejail.conf" ]; then
            log_message "Service '$base_name' is already configured to run in FireJail. Skipping."
        else
            securable_services+=("$base_name")
        fi
    fi
done

if [ ${#securable_services[@]} -eq 0 ]; then
    log_message "No new securable services found running on the system."
    exit 0
fi

log_step "Step 2: Interactive Hardening"
echo "The following running services can be sandboxed by FireJail:"
for service in "${securable_services[@]}"; do
    echo -e "  - ${CYAN}${service}${NC}"
done
echo ""

for service in "${securable_services[@]}"; do
    read -p "Do you want to secure the '${service}' service now? (y/n): " confirm
    if [[ "$confirm" == [yY] ]]; then
        secure_service "$service"
        echo "" # Add a newline for readability
    else
        log_message "Skipping '$service'."
    fi
done

log_step "Scan and hardening process complete."
exit 0