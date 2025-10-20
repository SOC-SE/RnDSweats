#!/bin/bash

# Honeypot Manager: Endlessh SSH Tarpit for MWCCDC Defense       #
# ---------------------------------------------------------------#
# Features:                                                      #
# - Menu-Driven: Install, Uninstall, Adjust Service, Quit        #
# - Secure Install/Uninstall with Spinners & Error Display       #
# - Adjust Configs: Delays, Logging, Client Limits (Apply/Revert)#
# - MWCCDC Aligned: Delay Red Team, Log for IR Reports (pg.13-17)#
# - Usage: Defensive Detection, No Offenses, Palo Alto NAT       #
# - NEW: Export Logs for IR (time window, optional filter, reusable dir) #
##################################################################

set -euo pipefail

# --- ASCII Banner ---
# (Room left here for custom ASCII; the provided one is already included below)
echo -e "\033[1;32m"
cat << "EOF"
################################################
# _   _                                    _   #
#| | | | ___  _ __   ___ _   _ _ __   ___ | |_ #
#| |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _ \| __|#
#|  _  | (_) | | | |  __/ |_| | |_) | (_) | |_ #
#|_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|#
#                        |___/|_|              #
################################################
EOF
echo -e "\033[0m"
echo "Honeypot Manager"
echo "--------------------------------------"

# --- Configuration & Colors ---
HONEYPOT_PORT=2222
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
CONFIG_DIR="/etc/endlessh"
CONFIG_FILE="$CONFIG_DIR/config"
STATE_FILE="$CONFIG_DIR/adjustments.state"  # Track adjustments
EXPORT_DIR_FILE="$CONFIG_DIR/export_dir.state"  # NEW: Track reusable export dir

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function (unchanged)
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "%c " "${spinstr:0:1}"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b"
    done
    printf " \b"
}

# Detect package manager (unchanged)
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        UPDATE_CMD="apt-get update -y"
        INSTALL_CMD="apt-get install -y"
        REMOVE_CMD="apt-get purge -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf check-update -y"
        INSTALL_CMD="dnf install -y"
        REMOVE_CMD="dnf remove -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum check-update -y"
        INSTALL_CMD="yum install -y"
        REMOVE_CMD="yum remove -y"
    else
        log_error "No supported package manager (apt, dnf, yum) found."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Root Check --- (unchanged)
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# --- Check for Legacy tpot --- (unchanged)
check_legacy_tpot() {
    if [ -d "/opt/tpot" ]; then
        log_warn "Legacy /opt/tpot directory found. Consider removing it if not needed: rm -rf /opt/tpot"
    fi
}

# --- Handle SELinux/AppArmor --- (unchanged)
handle_security_modules() {
    if command -v getenforce &> /dev/null && [ "$(getenforce)" = "Enforcing" ]; then
        log_info "SELinux detected and enforcing. Allowing port binding for Endlessh..."
        if command -v semanage &> /dev/null; then
            semanage port -a -t ssh_port_t -p tcp $HONEYPOT_PORT || log_warn "SELinux port labeling failed; manual check needed."
        else
            log_warn "semanage not available (install policycoreutils-python-utils); manual SELinux check needed."
        fi
    fi
    if command -v aa-status &> /dev/null && aa-status | grep -q "endlessh"; then
        log_info "AppArmor profile for Endlessh detected. Disabling if conflicting..."
        aa-disable /etc/apparmor.d/endlessh || log_warn "AppArmor disable failed; manual check needed."
    fi
}

# --- Check if Endlessh Installed --- (unchanged)
is_endlessh_installed() {
    command -v endlessh &> /dev/null
}

# --- Install OpenSSH Server for Real SSH Access --- (unchanged)
install_openssh() {
    if command -v sshd &> /dev/null; then
        log_info "OpenSSH server is already installed."
        return
    fi
    
    log_info "Installing OpenSSH server..."
    printf "Installing OpenSSH... "
    local err_file=$(mktemp)
    ( $UPDATE_CMD >/dev/null 2>"$err_file" &&
      $INSTALL_CMD openssh-server >/dev/null 2>>"$err_file" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""
        echo -e "${RED}Error during OpenSSH installation:${NC}"
        echo "$err_content"
        log_error "OpenSSH installation failed."
    fi
    echo ""

    # Post-install with spinner and error capture
    printf "Configuring OpenSSH service... "
    local err_file=$(mktemp)
    ( systemctl enable ssh >/dev/null 2>"$err_file"
      systemctl start ssh >/dev/null 2>>"$err_file" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""
        echo -e "${RED}Error during OpenSSH configuration:${NC}"
        echo "$err_content"
        log_error "OpenSSH configuration failed."
    fi
    echo ""

    if systemctl is-active --quiet ssh; then
        log_info "OpenSSH active on port 22."
    else
        log_error "OpenSSH failed to start."
    fi
}

# Attempt to build Endlessh from source on distros without a packaged version
build_endlessh_from_source() {
    log_warn "Falling back to source build for Endlessh (package not available)."
    local deps_installed=true
    if ! command -v git &> /dev/null || ! command -v make &> /dev/null || ! command -v gcc &> /dev/null; then
        log_info "Installing build prerequisites (git make gcc)..."
        if ! $INSTALL_CMD git make gcc >/dev/null 2>&1; then
            log_warn "Automatic install of build prerequisites failed. Install git/make/gcc manually."
            deps_installed=false
        fi
    fi
    if ! $deps_installed; then
        return 1
    fi

    local build_dir
    build_dir=$(mktemp -d)
    if ! git clone --depth 1 https://github.com/skeeto/endlessh.git "$build_dir/endlessh" >/dev/null 2>&1; then
        log_warn "Git clone failed (check connectivity)."
        rm -rf "$build_dir"
        return 1
    fi

    pushd "$build_dir/endlessh" >/dev/null || { rm -rf "$build_dir"; return 1; }
    if ! make >/dev/null 2>&1; then
        log_warn "Building Endlessh failed."
        popd >/dev/null
        rm -rf "$build_dir"
        return 1
    fi
    if ! install -m 755 endlessh /usr/local/bin/endlessh >/dev/null 2>&1; then
        log_warn "Installing Endlessh binary failed."
        popd >/dev/null
        rm -rf "$build_dir"
        return 1
    fi
    popd >/dev/null
    rm -rf "$build_dir"

    if [ ! -f /etc/systemd/system/endlessh.service ]; then
        cat << 'EOF' > /etc/systemd/system/endlessh.service
[Unit]
Description=Endlessh SSH Tarpit Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/endlessh -f /etc/endlessh/config
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload >/dev/null 2>&1
    log_info "Endlessh compiled from source and service file installed."
    return 0
}

# --- Install Endlessh --- (unchanged)
install_endlessh() {
    if is_endlessh_installed; then
        log_warn "Endlessh already installed."
        return 1
    fi
    log_info "Installing Endlessh..."
    printf "Installing Endlessh... "
    local err_file=$(mktemp)
    ( $UPDATE_CMD >/dev/null 2>"$err_file" &&
      $INSTALL_CMD endlessh >/dev/null 2>>"$err_file" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""
        echo -e "${RED}Error during Endlessh installation:${NC}"
        echo "$err_content"
        if ! build_endlessh_from_source; then
            log_error "Installation failed."
        fi
    fi
    echo ""

    # Post-install with spinner and error capture
    printf "Configuring Endlessh... "
    local err_file=$(mktemp)
    ( configure_endlessh >/dev/null 2>"$err_file" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""
        echo -e "${RED}Error during Endlessh configuration:${NC}"
        echo "$err_content"
        log_error "Configuration failed."
    fi
    echo ""

    test_honeypot
    print_usage_instructions
    return 0
}

# --- Uninstall Endlessh --- (unchanged)
uninstall_endlessh() {
    if ! is_endlessh_installed; then
        log_warn "Endlessh not installed."
        return 1
    fi
    log_info "Uninstalling Endlessh..."
    printf "Uninstalling Endlessh... "
    local err_file=$(mktemp)
    ( systemctl stop endlessh >/dev/null 2>"$err_file" || true
      systemctl disable endlessh >/dev/null 2>>"$err_file" || true
      $REMOVE_CMD endlessh >/dev/null 2>>"$err_file"
      rm -rf "$CONFIG_DIR" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ -n "$err_content" ]; then
        echo ""
        echo -e "${RED}Errors/Warnings:${NC}"
        echo "$err_content"
    fi
    if [ $exit_status -ne 0 ]; then
        log_error "Uninstallation failed."
    fi
    if [ -z "$err_content" ]; then
        echo ""
    fi
    log_info "Endlessh uninstalled."
    return 0
}

# --- Endlessh Configuration --- (unchanged)
configure_endlessh() {
    mkdir -p "$CONFIG_DIR" >/dev/null 2>&1
    cat << EOF > "$CONFIG_FILE"
Port ${HONEYPOT_PORT}
Delay 1000
MaxLineLength 32
LogLevel 2
EOF
    if command -v rsyslogd &> /dev/null; then
        echo "local0.* /var/log/endlessh.log" >> /etc/rsyslog.d/10-endlessh.conf
        if systemctl restart rsyslog >/dev/null 2>&1; then
            log_info "rsyslog restarted successfully."
        else
            log_warn "rsyslog restart failed; check status manually."
        fi
    fi
    if command -v mailx &> /dev/null; then
        echo "*/5 * * * * journalctl -u endlessh --since '5 minutes ago' | grep 'connection' | wc -l | xargs -I {} [ {} -gt 10 ] && echo 'High Endlessh attempts!' | mailx -s 'Honeypot Alert' team@email.com" > /etc/cron.d/endlessh-alert
    fi
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp >/dev/null 2>&1
        ufw allow "$HONEYPOT_PORT"/tcp >/dev/null 2>&1
        ufw reload >/dev/null 2>&1
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$HONEYPOT_PORT"/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    elif command -v iptables &> /dev/null; then
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1
        iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT >/dev/null 2>&1
        iptables-save > /etc/iptables.rules >/dev/null 2>&1
    fi
    systemctl enable endlessh >/dev/null 2>&1
    systemctl restart endlessh >/dev/null 2>&1
}

# --- Test Honeypot Locally --- (unchanged)
test_honeypot() {
    if ! command -v ssh &> /dev/null || ! command -v nc &> /dev/null; then
        $INSTALL_CMD openssh-client netcat-traditional >/dev/null 2>&1
    fi
    timeout 5 ssh -p ${HONEYPOT_PORT} localhost &> /dev/null
}

# --- Print Usage Instructions --- (unchanged, but added note on export)
print_usage_instructions() {
    log_info "Endlessh Honeypot installed successfully on port ${HONEYPOT_PORT}."
    log_info "How to Utilize and Run Endlessh (Aligned with MWCCDC 2025 Rules):"
    echo "- **Purpose**: Endlessh acts as an SSH tarpit honeypot to delay and detect Red Team reconnaissance/probes (e.g., brute-force attempts) without active countermeasures, keeping it purely defensive (per rules pg.13-14: No offensive activity like scans or attacks on other teams/Red Team)."
    echo "- **Setup and Exposure**: Configure via /etc/endlessh/config (e.g., adjust Delay for longer tarpits). Expose the port via Palo Alto NAT to a public IP (e.g., 172.25.20+team#.x per topology pg.19-21) to attract external probes while isolating from internal services."
    echo "- **Running and Monitoring**: Service starts automatically. Monitor logs for incident response: `journalctl -u endlessh -f` or `tail -f /var/log/endlessh.log` (if rsyslog configured). Log connections (e.g., source IPs, timelines) for IR reports (submit as PDF via NISE, focusing on exploitation events per rules pg.16-17)."
    echo "- **NEW: Log Export**: Use menu option 5 to export logs for IR reports by time window and optional filter."
    echo "- **Testing**: Locally: `ssh -p ${HONEYPOT_PORT} localhost` (should hang indefinitely). Externally: From another VM, `ssh -p ${HONEYPOT_PORT} <VM_IP>`. Avoid testing that could be seen as offensive (e.g., no mass scans)."
    echo "- **CCDC Alignment and Best Practices (2025 Research)**: Use to improve scoring by detecting unauthorized access without disrupting business tasks (pg.16: Points for preventing penetrations). Isolate honeypot to avoid resource drain or false positives. From 2025 trends (e.g., SecureMyOrg article), leverage for threat intel but ensure no internet-required updates (rules pg.15: Monitored usage). Historical CCDC outcomes show honeypots help in early detection; recommend team drills on log analysis for IR."
    echo "- **Security Notes**: Restrict access (e.g., firewall rules), monitor for high loads. If alerts configured, edit cron for team email notifications."
    log_warn "Ensure honeypot doesn't interfere with required services (e.g., real SSH on port 22) to maintain uptime scoring (rules pg.17)."
}

# --- Adjust Service --- (unchanged)
adjust_service() {
    if ! is_endlessh_installed; then
        log_warn "Endlessh not installed."
        return
    fi
    touch "$STATE_FILE"
    local configs=(
        "Increase delay to 5000ms"
        "Set max clients to 32"
        "Enable verbose logging"
        "Bind to specific IP"
    )
    log_info "Current configs:"
    cat "$STATE_FILE" || echo "None."
    log_info "Select to apply/revert (0 exit):"
    for i in "${!configs[@]}"; do
        echo "$((i+1))) ${configs[i]}"
    done
    read -p "Choice: " choice
    if [ "$choice" -eq 0 ]; then return; fi
    if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#configs[@]}" ]; then
        log_warn "Invalid."
        return
    fi
    local conf="${configs[$((choice-1))]}"
    if grep -q "^$conf$" "$STATE_FILE"; then
        revert_config "$conf"
    else
        apply_config "$conf"
    fi
    systemctl restart endlessh
    log_info "Adjusted and restarted."
}

apply_config() {  # (unchanged)
    local conf=$1
    case "$conf" in
        "Increase delay to 5000ms")
            echo "Delay 5000" >> "$CONFIG_FILE" ;;
        "Set max clients to 32")
            echo "MaxClients 32" >> "$CONFIG_FILE" ;;
        "Enable verbose logging")
            echo "LogLevel 2" >> "$CONFIG_FILE" ;;
        "Bind to specific IP")
            read -p "IP: " IP
            if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then log_error "Invalid IP."; fi
            echo "BindHost $IP" >> "$CONFIG_FILE" ;;
    esac
    echo "$conf" >> "$STATE_FILE"
    log_info "Applied: $conf"
}

revert_config() {  # (unchanged)
    local conf=$1
    case "$conf" in
        "Increase delay to 5000ms")
            sed -i '/Delay 5000/d' "$CONFIG_FILE" ;;
        "Set max clients to 32")
            sed -i '/MaxClients 32/d' "$CONFIG_FILE" ;;
        "Enable verbose logging")
            sed -i '/LogLevel 2/d' "$CONFIG_FILE" ;;
        "Bind to specific IP")
            sed -i '/BindHost /d' "$CONFIG_FILE" ;;
    esac
    sed -i "/^$conf$/d" "$STATE_FILE"
    log_info "Reverted: $conf"
}

# --- NEW: Export Logs for IR ---
export_logs() {
    if ! is_endlessh_installed; then
        log_warn "Endlessh not installed. Cannot export logs."
        return
    fi

    # Determine log source
    local log_file="/var/log/endlessh.log"
    local use_journal=false
    if [ ! -f "$log_file" ]; then
        use_journal=true
        log_info "Using journalctl for logs (rsyslog not configured)."
    else
        log_info "Using $log_file for logs."
    fi

    # Get or set export directory
    local export_dir
    if [ -f "$EXPORT_DIR_FILE" ]; then
        export_dir=$(cat "$EXPORT_DIR_FILE")
        log_info "Reusing existing export directory: $export_dir"
    else
        read -p "Enter export directory (default: ~/endlessh_exports): " export_dir
        export_dir=${export_dir:-~/endlessh_exports}
        mkdir -p "$export_dir" || log_error "Failed to create directory $export_dir"
        echo "$export_dir" > "$EXPORT_DIR_FILE"
        log_info "Created and set export directory: $export_dir"
    fi

    # Get time window
    read -p "Enter start time (YYYY-MM-DD HH:MM, e.g., 2025-07-22 14:00): " start_time
    read -p "Enter end time (YYYY-MM-DD HH:MM, e.g., 2025-07-22 15:00): " end_time
    if [[ ! "$start_time" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]] || [[ ! "$end_time" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]]; then
        log_error "Invalid time format."
    fi

    # Optional keyword filter
    read -p "Enter optional keyword filter (e.g., IP or 'connection', leave blank for none): " keyword

    # Generate timestamped output file
    local timestamp=$(date +%Y%m%d_%H%M)
    local output_file="$export_dir/endlessh_logs_${timestamp}.txt"

    # Extract logs
    if $use_journal; then
        local cmd="journalctl -u endlessh --since '$start_time' --until '$end_time'"
        if [ -n "$keyword" ]; then
            cmd="$cmd | grep -i '$keyword'"
        fi
        eval "$cmd" > "$output_file" || log_error "Log extraction failed."
    else
        # For file, use awk to filter by time (assuming standard syslog format)
        local awk_filter="awk -v start=\"$start_time\" -v end=\"$end_time\" '\$1\" \"\$2 >= start && \$1\" \"\$2 <= end'"
        if [ -n "$keyword" ]; then
            awk_filter="$awk_filter | grep -i '$keyword'"
        fi
        eval "cat $log_file | $awk_filter > '$output_file'" || log_error "Log extraction failed."
    fi

    log_info "Logs exported to $output_file for IR report."
}

# --- TeamPack compliance: confirm authorized environment ---
teampack_confirm() {
    read -p "Confirm you will run this only on your authorized team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}
teampack_confirm

# --- Menu (Launches on script start) ---
prompt_menu() {
    while true; do
        log_info "Options:"
        echo "1) Install Honeypot"
        echo "2) Uninstall Honeypot"
        echo "3) Adjust Service"
        echo "4) Export Logs for IR"  # NEW option
        echo "5) Quit"  # Shifted
        read -p "Choice (1-5): " opt
        case $opt in
            1) install_openssh; install_endlessh ;;
            2) uninstall_endlessh ;;
            3) adjust_service ;;
            4) export_logs ;;  # NEW
            5) log_info "Exiting."; exit 0 ;;
            *) log_warn "Invalid choice." ;;
        esac
    done
}

# --- Main Logic ---
main() {
    check_root
    check_legacy_tpot
    detect_pkg_manager
    handle_security_modules
    prompt_menu  # Script now starts here, showing menu immediately
}

main "$@"