#!/bin/bash

# ====================================================================================
# FireJail Service Scanner and Hardening Script (Competition Hardened)
# ====================================================================================

# --- Script Configuration ---
set -o pipefail

# --- Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- SAFEGUARDS ---
# CRITICAL: Services found in this list will NEVER be touched.
# 1. sshd/ssh: Never sandbox remote access.
# 2. docker: Has its own containerization, nesting firejail causes issues.
# 3. fail2ban: Needs extensive log access that firejail often blocks.
# 4. vmtoolsd/qemu-guest-agent: Needed for competition infrastructure often.
EXCLUDED_SERVICES=("sshd" "ssh" "docker" "fail2ban" "rsyslog" "NetworkManager" "vmtoolsd" "qemu-guest-agent")

log_message() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_danger()  { echo -e "${RED}[DANGER]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}--- $1 ---"${NC}; }

if [ "$(id -u)" -ne 0 ]; then
  log_warning "Run as root."
  exit 1
fi

if ! command -v firejail &> /dev/null; then
    log_warning "FireJail not installed."
    exit 1
fi

secure_service() {
    local service_name="$1"
    local service_file="${service_name}.service"

    # --- EXCLUSION CHECK ---
    for excluded in "${EXCLUDED_SERVICES[@]}"; do
        if [[ "$service_name" == "$excluded" ]]; then
            log_warning "Skipping '$service_name' (Explicitly Excluded for Safety)."
            return 0
        fi
    done

    log_message "Preparing to secure '$service_name'..."

    # Parse ExecStart
    local original_exec_start
    original_exec_start=$(systemctl show -p ExecStart --value "$service_file")

    if [ -z "$original_exec_start" ]; then
        log_warning "Could not parse ExecStart for '$service_name'. Skipping."
        return 1
    fi

    # Cleaning the SystemD Output
    local exec_command_line
    exec_command_line=$(echo "$original_exec_start" | sed -e "s/^{ path=\([^;]*\); args=\[\([^]]*\)\]; .*}/\1 \2/" -e 's/"//g' -e 's/;/ /g')

    # Validating the parse
    if [[ -z "$exec_command_line" ]]; then
         log_warning "Failed to extract command line. Systemd output was: $original_exec_start"
         return 1
    fi

    local firejail_path=$(command -v firejail)
    local new_exec_start="${firejail_path} ${exec_command_line}"

    log_step "Proposed Change for '$service_name'"
    echo "Command: $new_exec_start"
    
    # default to NO for safety in competitions
    read -p "Apply this change? (y/N): " apply_confirm
    if [[ "$apply_confirm" != [yY] ]]; then
        return 0
    fi

    local override_dir="/etc/systemd/system/${service_file}.d"
    mkdir -p "$override_dir"
    local override_file="${override_dir}/firejail.conf"
    
    cat > "$override_file" <<EOF
[Service]
ExecStart=
ExecStart=${new_exec_start}
EOF

    log_message "Reloading systemd and restarting '$service_name'..."
    systemctl daemon-reload
    systemctl restart "$service_name"

    sleep 2
    if systemctl is-active --quiet "$service_name"; then
        log_message "'$service_name' restarted successfully."
        # Optional: Check firejail --list, though it can be flaky with some services
    else
        log_danger "'$service_name' FAILED TO START!"
        log_message "Automatically reverting..."
        rm -f "$override_file"
        systemctl daemon-reload
        systemctl restart "$service_name"
        log_message "Reverted to original state."
    fi
}

log_step "Scanning for Securable Services"
PROFILE_DIR="/etc/firejail"
mapfile -t running_services < <(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')
securable_services=()

for service in "${running_services[@]}"; do
    base_name=${service%.service}
    if [ -f "${PROFILE_DIR}/${base_name}.profile" ]; then
        if [ ! -f "/etc/systemd/system/${service}.d/firejail.conf" ]; then
            securable_services+=("$base_name")
        fi
    fi
done

if [ ${#securable_services[@]} -eq 0 ]; then
    log_message "No new securable services found."
    exit 0
fi

echo "Found candidates: ${securable_services[*]}"
for service in "${securable_services[@]}"; do
    secure_service "$service"
done