#!/bin/bash

# Honeypot Script

set -euo pipefail

# --- ASCII Banner ---
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
echo "----------------"

# --- Configuration & Colors ---
HONEYPOT_PORT=2222
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
CONFIG_DIR="/etc/endlessh"
CONFIG_FILE="$CONFIG_DIR/config"
STATE_FILE="$CONFIG_DIR/adjustments.state"
EXPORT_DIR_FILE="$CONFIG_DIR/export_dir.state"

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

check_legacy_tpot() {
    if [ -d "/opt/tpot" ]; then
        log_warn "Legacy /opt/tpot directory found. Consider removing it if not needed."
    fi
}

handle_security_modules() {
    if command -v getenforce &> /dev/null && [ "$(getenforce)" = "Enforcing" ]; then
        log_info "SELinux enforcing. Allowing port binding..."
        command -v semanage &> /dev/null && semanage port -a -t ssh_port_t -p tcp $HONEYPOT_PORT || log_warn "SELinux port labeling failed."
    fi
    if command -v aa-status &> /dev/null && aa-status | grep -q "endlessh"; then
        log_info "AppArmor profile detected. Disabling if conflicting..."
        aa-disable /etc/apparmor.d/endlessh || log_warn "AppArmor disable failed."
    fi
}

is_endlessh_installed() {
    command -v endlessh &> /dev/null
}

install_openssh() {
    command -v sshd &> /dev/null || {
        log_info "Installing OpenSSH server..."
        printf "Installing OpenSSH... "
        local err_file=$(mktemp)
        ( $UPDATE_CMD >/dev/null 2>"$err_file"
          $INSTALL_CMD openssh-server >/dev/null 2>>"$err_file" ) &
        spinner $!
        wait
        local exit_status=$?
        local err_content=$(cat "$err_file")
        rm -f "$err_file"
        [ $exit_status -ne 0 ] && {
            echo ""
            echo -e "${RED}Error during OpenSSH installation:${NC}"
            echo "$err_content"
            log_error "OpenSSH installation failed."
        }
        echo ""
        printf "Configuring OpenSSH service... "
        local err_file=$(mktemp)
        ( systemctl enable ssh >/dev/null 2>"$err_file"
          systemctl start ssh >/dev/null 2>>"$err_file" ) &
        spinner $!
        wait
        rm -f "$err_file"
        systemctl is-active --quiet ssh || log_error "OpenSSH failed to start."
        echo ""
        log_info "OpenSSH active on port 22."
    }
}

build_endlessh_from_source() {
    log_warn "Building Endlessh from source."
    local deps_installed=true
    for dep in git make gcc; do
        command -v "$dep" &> /dev/null || {
            $INSTALL_CMD "$dep" >/dev/null 2>&1 || deps_installed=false
        }
    done
    [[ $deps_installed == false ]] && return 1

    local build_dir=$(mktemp -d)
    git clone --depth 1 https://github.com/skeeto/endlessh.git "$build_dir/endlessh" || { rm -rf "$build_dir"; return 1; }
    pushd "$build_dir/endlessh" >/dev/null
    make >/dev/null || { popd >/dev/null; rm -rf "$build_dir"; return 1; }
    install -m 755 endlessh /usr/local/bin/endlessh >/dev/null || { popd >/dev/null; rm -rf "$build_dir"; return 1; }
    popd >/dev/null
    rm -rf "$build_dir"

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
    systemctl daemon-reload >/dev/null 2>&1
    log_info "Endlessh built from source."
}

install_endlessh() {
    is_endlessh_installed && { log_warn "Endlessh already installed."; return 1; }
    log_info "Installing Endlessh..."
    printf "Installing Endlessh... "
    local err_file=$(mktemp)
    ( $UPDATE_CMD >/dev/null 2>"$err_file"
      $INSTALL_CMD endlessh >/dev/null 2>>"$err_file" ) &
    spinner $!
    wait
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    [ $exit_status -ne 0 ] && {
        echo ""
        build_endlessh_from_source || log_error "Endlessh installation failed."
    }
    echo ""
    printf "Configuring Endlessh... "
    local err_file=$(mktemp)
    configure_endlessh >/dev/null 2>"$err_file"
    rm -f "$err_file"
    test_honeypot
    print_usage_instructions
}

uninstall_endlessh() {
    ! is_endlessh_installed && { log_warn "Endlessh not installed."; return 1; }
    log_info "Uninstalling Endlessh..."
    printf "Uninstalling Endlessh... "
    local err_file=$(mktemp)
    ( systemctl stop endlessh >/dev/null 2>"$err_file" || true
      systemctl disable endlessh >/dev/null 2>>"$err_file" || true
      $REMOVE_CMD endlessh >/dev/null 2>>"$err_file"
      rm -rf "$CONFIG_DIR" ) &
    spinner $!
    wait
    rm -f "$err_file"
    log_info "Endlessh uninstalled."
}

configure_endlessh() {
    mkdir -p "$CONFIG_DIR"
    cat << EOF > "$CONFIG_FILE"
Port ${HONEYPOT_PORT}
Delay 1000
MaxLineLength 32
LogLevel 2
EOF
    command -v rsyslogd &> /dev/null && {
        echo "local0.* /var/log/endlessh.log" >> /etc/rsyslog.d/10-endlessh.conf
        systemctl restart rsyslog >/dev/null 2>&1 || log_warn "rsyslog restart failed."
    }
    command -v ufw &> /dev/null && {
        ufw allow 22/tcp >/dev/null 2>&1
        ufw allow "$HONEYPOT_PORT"/tcp >/dev/null 2>&1
        ufw reload >/dev/null 2>&1
    } || command -v firewall-cmd &> /dev/null && {
        firewall-cmd --permanent --add-port=22/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$HONEYPOT_PORT"/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    }
    systemctl enable endlessh >/dev/null 2>&1
    systemctl restart endlessh >/dev/null 2>&1
}

test_honeypot() {
    command -v ssh &> /dev/null || command -v nc &> /dev/null || $INSTALL_CMD openssh-client netcat-traditional >/dev/null 2>&1
    timeout 5 ssh -p ${HONEYPOT_PORT} localhost &> /dev/null || true
}

print_usage_instructions() {
    log_info "Endlessh honeypot on port ${HONEYPOT_PORT}."
    log_info "Monitor: journalctl -u endlessh -f or tail -f /var/log/endlessh.log"
    log_info "Test locally: ssh -p ${HONEYPOT_PORT} localhost (hangs)"
    log_warn "Restrict access via firewall."
}

adjust_service() {
    is_endlessh_installed || { log_warn "Endlessh not installed."; return; }
    touch "$STATE_FILE"
    local configs=( "Increase delay to 5000ms" "Set max clients to 32" "Enable verbose logging" "Bind to specific IP" )
    log_info "Current configs:"
    cat "$STATE_FILE" 2>/dev/null || echo "None."
    log_info "Select (0 exit):"
    for i in "${!configs[@]}"; do echo "$((i+1))) ${configs[i]}"; done
    read -p "Choice: " choice
    [[ $choice -eq 0 ]] && return
    [[ $choice -lt 1 || $choice -gt ${#configs[@]} ]] && { log_warn "Invalid."; return; }
    local conf="${configs[$((choice-1))]}"
    if grep -q "^$conf$" "$STATE_FILE"; then
        revert_config "$conf"
    else
        apply_config "$conf"
    fi
    systemctl restart endlessh
    log_info "Adjusted."
}

apply_config() {
    local conf=$1
    case "$conf" in
        "Increase delay to 5000ms") echo "Delay 5000" >> "$CONFIG_FILE" ;;
        "Set max clients to 32") echo "MaxClients 32" >> "$CONFIG_FILE" ;;
        "Enable verbose logging") echo "LogLevel 2" >> "$CONFIG_FILE" ;;
        "Bind to specific IP")
            read -p "IP: " IP
            [[ ! $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && log_error "Invalid IP."
            echo "BindHost $IP" >> "$CONFIG_FILE" ;;
    esac
    echo "$conf" >> "$STATE_FILE"
}

revert_config() {
    local conf=$1
    case "$conf" in
        "Increase delay to 5000ms") sed -i '/Delay 5000/d' "$CONFIG_FILE" ;;
        "Set max clients to 32") sed -i '/MaxClients 32/d' "$CONFIG_FILE" ;;
        "Enable verbose logging") sed -i '/LogLevel 2/d' "$CONFIG_FILE" ;;
        "Bind to specific IP") sed -i '/BindHost /d' "$CONFIG_FILE" ;;
    esac
    sed -i "/^$conf$/d" "$STATE_FILE"
}

export_logs() {
    is_endlessh_installed || { log_warn "Endlessh not installed."; return; }
    local log_file="/var/log/endlessh.log"
    local use_journal=false
    [[ ! -f $log_file ]] && use_journal=true
    local export_dir=${export_dir:-~/endlessh_exports}
    mkdir -p "$export_dir"
    read -p "Start time (YYYY-MM-DD HH:MM): " start_time
    read -p "End time (YYYY-MM-DD HH:MM): " end_time
    read -p "Keyword filter (blank=none): " keyword
    local timestamp=$(date +%Y%m%d_%H%M)
    local output_file="$export_dir/endlessh_logs_${timestamp}.txt"
    if $use_journal; then
        local cmd="journalctl -u endlessh --since '$start_time' --until '$end_time'"
        [[ -n $keyword ]] && cmd+=" | grep -i '$keyword'"
        eval "$cmd" > "$output_file"
    else
        awk -v start="$start_time" -v end="$end_time" -v kw="$keyword" '
            $1" "$2 >= start && $1" "$2 <= end {print}
            kw && /kw/ {print}' "$log_file" > "$output_file"
    fi
    log_info "Exported to $output_file"
}

prompt_menu() {
    while true; do
        log_info "Options:"
        echo "1) Install Honeypot"
        echo "2) Uninstall Honeypot"
        echo "3) Adjust Service"
        echo "4) Export Logs"
        echo "5) Quit"
        read -p "Choice (1-5): " opt
        case $opt in
            1) install_openssh; install_endlessh ;;
            2) uninstall_endlessh ;;
            3) adjust_service ;;
            4) export_logs ;;
            5) log_info "Exiting."; exit 0 ;;
            *) log_warn "Invalid." ;;
        esac
    done
}

main() {
    check_root
    check_legacy_tpot
    detect_pkg_manager
    handle_security_modules
    prompt_menu
}

main "$@"