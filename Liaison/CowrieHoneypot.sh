#!/bin/bash

# Cowrie SSH/Telnet Honeypot — Deployment & Management Script
#
# Deploys Cowrie as a medium-interaction SSH honeypot that captures:
#   - Login credentials (username + password)
#   - Full interactive shell sessions (command transcripts)
#   - File downloads/uploads (malware samples)
#   - Connection metadata (source IP, duration, client fingerprint)
#
# Cowrie runs its own self-contained SSH server — no system sshd needed.
# All logs are JSON-structured for easy Splunk/SIEM ingestion.
#
# USAGE (run as root):
#   ./CowrieHoneypot.sh install       Install and start Cowrie
#   ./CowrieHoneypot.sh uninstall     Stop and remove Cowrie
#   ./CowrieHoneypot.sh status        Show service status and recent activity
#   ./CowrieHoneypot.sh logs          Tail live JSON logs
#   ./CowrieHoneypot.sh sessions      Show recent captured sessions
#   ./CowrieHoneypot.sh creds         Show captured credentials
#   ./CowrieHoneypot.sh downloads     List captured files/malware
#   ./CowrieHoneypot.sh splunk        Configure Splunk forwarder for Cowrie logs
#   ./CowrieHoneypot.sh               Interactive menu

set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────────────
COWRIE_USER="cowrie"
COWRIE_HOME="/opt/cowrie"
COWRIE_REPO="https://github.com/cowrie/cowrie.git"
COWRIE_VENV="${COWRIE_HOME}/cowrie-env"
COWRIE_CFG="${COWRIE_HOME}/etc/cowrie.cfg"
COWRIE_LOG_DIR="${COWRIE_HOME}/var/log/cowrie"
COWRIE_DL_DIR="${COWRIE_HOME}/var/lib/cowrie/downloads"
COWRIE_TTY_DIR="${COWRIE_HOME}/var/lib/cowrie/tty"

# Listening ports — set the SSH listen port here.
# Use iptables/firewall to redirect external port 22 -> this port if desired.
LISTEN_SSH_PORT=2222
LISTEN_TELNET_PORT=2223
LISTEN_ENABLED_TELNET="false"

# Hostname the fake shell presents to attackers
FAKE_HOSTNAME="svr01"

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────────────────
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_fatal() { log_error "$1"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || log_fatal "This script must be run as root."
}

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
        UPDATE_CMD="apt-get update -y"
        INSTALL_CMD="apt-get install -y"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf makecache -y"
        INSTALL_CMD="dnf install -y"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum makecache"
        INSTALL_CMD="yum install -y"
    else
        log_fatal "No supported package manager found (apt, dnf, yum)."
    fi
}

# ── Install ─────────────────────────────────────────────────────────────────
install_dependencies() {
    log_info "Installing system dependencies..."
    $UPDATE_CMD >/dev/null 2>&1

    local deps_common="git python3 python3-venv python3-pip python3-dev libssl-dev libffi-dev gcc make"
    local deps_extra=""

    case "$PKG_MANAGER" in
        apt)
            deps_extra="build-essential libpython3-dev"
            ;;
        dnf|yum)
            deps_extra="python3-devel openssl-devel libffi-devel redhat-rpm-config"
            ;;
    esac

    $INSTALL_CMD $deps_common $deps_extra >/dev/null 2>&1 || {
        # Some packages may have different names; install what we can
        for pkg in $deps_common $deps_extra; do
            $INSTALL_CMD "$pkg" >/dev/null 2>&1 || true
        done
    }
    log_info "Dependencies installed."
}

create_cowrie_user() {
    if id "$COWRIE_USER" &>/dev/null; then
        log_info "User '$COWRIE_USER' already exists."
        return
    fi
    log_info "Creating system user '$COWRIE_USER'..."
    useradd --system --shell /bin/false --home-dir "$COWRIE_HOME" --create-home "$COWRIE_USER"
}

clone_cowrie() {
    if [[ -d "${COWRIE_HOME}/src" ]]; then
        log_info "Cowrie source already present. Pulling latest..."
        cd "$COWRIE_HOME"
        sudo -u "$COWRIE_USER" git pull --quiet 2>/dev/null || true
        return
    fi

    log_info "Cloning Cowrie repository..."
    if [[ -d "$COWRIE_HOME" ]]; then
        # Home exists from useradd but is empty
        chown "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_HOME"
    fi

    # Clone into a temp dir, then move contents (git clone needs empty dir)
    local tmp_dir
    tmp_dir=$(mktemp -d)
    git clone --quiet --depth 1 "$COWRIE_REPO" "$tmp_dir/cowrie"

    # Check for vendored fallback if clone fails
    if [[ ! -d "$tmp_dir/cowrie/src" ]]; then
        local vendor_src
        vendor_src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../vendor/cowrie"
        if [[ -d "$vendor_src" ]]; then
            log_warn "Git clone failed. Using vendored copy..."
            rm -rf "$tmp_dir/cowrie"
            cp -r "$vendor_src" "$tmp_dir/cowrie"
        else
            rm -rf "$tmp_dir"
            log_fatal "Failed to clone Cowrie and no vendored copy available."
        fi
    fi

    cp -a "$tmp_dir/cowrie/." "$COWRIE_HOME/"
    rm -rf "$tmp_dir"
    chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_HOME"
    log_info "Cowrie cloned to ${COWRIE_HOME}."
}

setup_virtualenv() {
    log_info "Setting up Python virtual environment..."
    if [[ ! -d "$COWRIE_VENV" ]]; then
        sudo -u "$COWRIE_USER" python3 -m venv "$COWRIE_VENV"
    fi

    sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --quiet --upgrade pip setuptools wheel 2>/dev/null
    sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --quiet -r "${COWRIE_HOME}/requirements.txt" 2>/dev/null

    log_info "Python environment ready."
}

configure_cowrie() {
    log_info "Writing Cowrie configuration..."

    # Start from the default config if it exists
    if [[ -f "${COWRIE_HOME}/etc/cowrie.cfg.dist" && ! -f "$COWRIE_CFG" ]]; then
        sudo -u "$COWRIE_USER" cp "${COWRIE_HOME}/etc/cowrie.cfg.dist" "$COWRIE_CFG"
    fi

    # Write our configuration
    cat > "$COWRIE_CFG" <<COWRIECFG
# ─── Cowrie Configuration ───────────────────────────────────────────────────
# Generated by CowrieHoneypot.sh — edit as needed

[honeypot]
hostname = ${FAKE_HOSTNAME}
timezone = UTC
log_path = ${COWRIE_LOG_DIR}
download_path = ${COWRIE_DL_DIR}
ttylog_path = ${COWRIE_TTY_DIR}
contents_path = ${COWRIE_HOME}/honeyfs
txtcmds_path = ${COWRIE_HOME}/txtcmds
share_path = ${COWRIE_HOME}/share/cowrie

# Capture all file download attempts
download_limit_size = 10485760

# ─── SSH Settings ───────────────────────────────────────────────────────────
[ssh]
enabled = true
listen_endpoints = tcp:${LISTEN_SSH_PORT}:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6

# ─── Telnet Settings ───────────────────────────────────────────────────────
[telnet]
enabled = ${LISTEN_ENABLED_TELNET}
listen_endpoints = tcp:${LISTEN_TELNET_PORT}:interface=0.0.0.0

# ─── Logging — JSON (primary, for SIEM/Splunk) ─────────────────────────────
[output_jsonlog]
enabled = true
logfile = ${COWRIE_LOG_DIR}/cowrie.json

# ─── Logging — Text (human-readable) ───────────────────────────────────────
[output_textlog]
enabled = true
logfile = ${COWRIE_LOG_DIR}/cowrie.log
COWRIECFG

    chown "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_CFG"

    # Ensure log and data directories exist
    mkdir -p "$COWRIE_LOG_DIR" "$COWRIE_DL_DIR" "$COWRIE_TTY_DIR"
    chown -R "$COWRIE_USER":"$COWRIE_USER" "${COWRIE_HOME}/var"

    # Accept any username/password — capture everything
    local userdb="${COWRIE_HOME}/etc/userdb.txt"
    cat > "$userdb" <<'USERDB'
# Format: username:uid:password
# '*' as username or password = accept any
*:0:*
USERDB
    chown "$COWRIE_USER":"$COWRIE_USER" "$userdb"

    log_info "Configuration written to ${COWRIE_CFG}."
}

create_systemd_unit() {
    log_info "Creating systemd service..."
    cat > /etc/systemd/system/cowrie.service <<UNIT
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${COWRIE_USER}
Group=${COWRIE_USER}
WorkingDirectory=${COWRIE_HOME}
ExecStart=${COWRIE_VENV}/bin/python3 ${COWRIE_HOME}/src/cowrie/__main__.py start --nodaemon
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${COWRIE_HOME}/var

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    log_info "Systemd unit created."
}

setup_firewall() {
    log_info "Configuring iptables rules..."

    # Allow inbound SSH (port 22) — Cowrie will receive this via NAT redirect
    if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        log_info "Allowed inbound TCP/22."
    fi

    # Allow Cowrie's listen port directly (for local testing / direct connections)
    if ! iptables -C INPUT -p tcp --dport "$LISTEN_SSH_PORT" -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p tcp --dport "$LISTEN_SSH_PORT" -j ACCEPT
        log_info "Allowed inbound TCP/${LISTEN_SSH_PORT}."
    fi

    # NAT redirect: external port 22 → Cowrie's listen port
    if ! iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$LISTEN_SSH_PORT" 2>/dev/null; then
        iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$LISTEN_SSH_PORT"
        log_info "NAT redirect: TCP/22 -> TCP/${LISTEN_SSH_PORT}."
    fi

    if [[ "$LISTEN_ENABLED_TELNET" == "true" ]]; then
        if ! iptables -C INPUT -p tcp --dport "$LISTEN_TELNET_PORT" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p tcp --dport "$LISTEN_TELNET_PORT" -j ACCEPT
            log_info "Allowed inbound TCP/${LISTEN_TELNET_PORT}."
        fi
    fi

    log_info "iptables rules configured."
}

start_cowrie() {
    systemctl enable cowrie >/dev/null 2>&1
    systemctl start cowrie

    # Wait briefly and verify
    sleep 3
    if systemctl is-active --quiet cowrie; then
        log_info "Cowrie is running."
    else
        log_error "Cowrie failed to start. Check: journalctl -u cowrie -n 50"
        return 1
    fi
}

do_install() {
    log_info "Installing Cowrie honeypot..."
    echo ""
    install_dependencies
    create_cowrie_user
    clone_cowrie
    setup_virtualenv
    configure_cowrie
    create_systemd_unit
    setup_firewall
    start_cowrie

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} Cowrie honeypot installed and running${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e " SSH listener:    ${CYAN}port ${LISTEN_SSH_PORT}${NC}"
    [[ "$LISTEN_ENABLED_TELNET" == "true" ]] && \
        echo -e " Telnet listener: ${CYAN}port ${LISTEN_TELNET_PORT}${NC}"
    echo -e " JSON logs:       ${CYAN}${COWRIE_LOG_DIR}/cowrie.json${NC}"
    echo -e " Text logs:       ${CYAN}${COWRIE_LOG_DIR}/cowrie.log${NC}"
    echo -e " Downloads:       ${CYAN}${COWRIE_DL_DIR}/${NC}"
    echo -e " Sessions:        ${CYAN}${COWRIE_TTY_DIR}/${NC}"
    echo ""
    echo -e " ${YELLOW}Port 22 is NAT-redirected to Cowrie automatically.${NC}"
    echo ""
}

# ── Uninstall ───────────────────────────────────────────────────────────────
do_uninstall() {
    log_info "Uninstalling Cowrie..."

    systemctl stop cowrie 2>/dev/null || true
    systemctl disable cowrie 2>/dev/null || true
    rm -f /etc/systemd/system/cowrie.service
    systemctl daemon-reload 2>/dev/null || true

    # Ask before deleting data
    if [[ -d "$COWRIE_HOME" ]]; then
        echo -e "${YELLOW}Delete all Cowrie data (logs, captured files, sessions)?${NC}"
        read -r -p "[y/N] " answer </dev/tty
        if [[ "$answer" =~ ^[Yy] ]]; then
            rm -rf "$COWRIE_HOME"
            log_info "Cowrie data deleted."
        else
            log_info "Data preserved at ${COWRIE_HOME}."
        fi
    fi

    if id "$COWRIE_USER" &>/dev/null; then
        userdel "$COWRIE_USER" 2>/dev/null || true
    fi

    log_info "Cowrie uninstalled."
}

# ── Status ──────────────────────────────────────────────────────────────────
do_status() {
    echo -e "${BOLD}── Cowrie Status ──${NC}"
    echo ""

    if systemctl is-active --quiet cowrie 2>/dev/null; then
        echo -e "Service: ${GREEN}running${NC}"
    else
        echo -e "Service: ${RED}stopped${NC}"
    fi

    # Listening ports
    if command -v ss &>/dev/null; then
        echo ""
        echo -e "${CYAN}Listening ports:${NC}"
        ss -tlnp 2>/dev/null | grep -E ":(${LISTEN_SSH_PORT}|${LISTEN_TELNET_PORT})\b" || echo "  None detected"
    fi

    # Log stats
    local json_log="${COWRIE_LOG_DIR}/cowrie.json"
    if [[ -f "$json_log" ]]; then
        echo ""
        local total_events login_attempts unique_ips
        total_events=$(wc -l < "$json_log")
        login_attempts=$(grep -c '"eventid":"cowrie.login' "$json_log" 2>/dev/null || echo 0)
        unique_ips=$(grep -oP '"src_ip":"\K[^"]+' "$json_log" 2>/dev/null | sort -u | wc -l)

        echo -e "${CYAN}Statistics:${NC}"
        echo "  Total events:     ${total_events}"
        echo "  Login attempts:   ${login_attempts}"
        echo "  Unique source IPs: ${unique_ips}"

        # Recent activity
        echo ""
        echo -e "${CYAN}Last 5 events:${NC}"
        tail -5 "$json_log" | while IFS= read -r line; do
            local ts eid src
            ts=$(echo "$line" | grep -oP '"timestamp":"\K[^"]+' || echo "?")
            eid=$(echo "$line" | grep -oP '"eventid":"\K[^"]+' || echo "?")
            src=$(echo "$line" | grep -oP '"src_ip":"\K[^"]+' || echo "?")
            echo "  ${ts}  ${eid}  from ${src}"
        done
    else
        echo ""
        echo "  No log data yet."
    fi
}

# ── Logs ────────────────────────────────────────────────────────────────────
do_logs() {
    local json_log="${COWRIE_LOG_DIR}/cowrie.json"
    if [[ ! -f "$json_log" ]]; then
        log_warn "No JSON log found at ${json_log}."
        log_info "Try: journalctl -u cowrie -f"
        return
    fi
    log_info "Tailing ${json_log} (Ctrl+C to stop)..."
    tail -f "$json_log"
}

# ── Captured Sessions ───────────────────────────────────────────────────────
do_sessions() {
    local json_log="${COWRIE_LOG_DIR}/cowrie.json"
    if [[ ! -f "$json_log" ]]; then
        echo "No log data yet."
        return
    fi

    echo -e "${BOLD}── Recent Sessions ──${NC}"
    echo ""

    # Show sessions with commands executed
    grep '"eventid":"cowrie.command.input"' "$json_log" 2>/dev/null | tail -20 | while IFS= read -r line; do
        local ts src sess cmd
        ts=$(echo "$line" | grep -oP '"timestamp":"\K[^"]+' || echo "?")
        src=$(echo "$line" | grep -oP '"src_ip":"\K[^"]+' || echo "?")
        sess=$(echo "$line" | grep -oP '"session":"\K[^"]+' || echo "?")
        cmd=$(echo "$line" | grep -oP '"input":"\K[^"]+' || echo "?")
        echo -e "  ${CYAN}${ts}${NC}  ${src}  [${sess}]  ${YELLOW}\$ ${cmd}${NC}"
    done

    local count
    count=$(grep -c '"eventid":"cowrie.command.input"' "$json_log" 2>/dev/null || echo 0)
    echo ""
    echo "Total commands captured: ${count}"
}

# ── Captured Credentials ────────────────────────────────────────────────────
do_creds() {
    local json_log="${COWRIE_LOG_DIR}/cowrie.json"
    if [[ ! -f "$json_log" ]]; then
        echo "No log data yet."
        return
    fi

    echo -e "${BOLD}── Captured Credentials ──${NC}"
    echo ""
    echo -e "  ${BOLD}Source IP         Username         Password${NC}"
    echo "  ──────────────── ──────────────── ────────────────"

    grep '"eventid":"cowrie.login' "$json_log" 2>/dev/null | while IFS= read -r line; do
        local src user pass success
        src=$(echo "$line" | grep -oP '"src_ip":"\K[^"]+' || echo "?")
        user=$(echo "$line" | grep -oP '"username":"\K[^"]+' || echo "?")
        pass=$(echo "$line" | grep -oP '"password":"\K[^"]+' || echo "?")
        success=$(echo "$line" | grep -oP '"eventid":"cowrie.login.\K[^"]+' || echo "?")
        if [[ "$success" == "success" ]]; then
            echo -e "  ${src}  ${user}  ${pass}  ${GREEN}(accepted)${NC}"
        else
            echo -e "  ${src}  ${user}  ${pass}  ${RED}(rejected)${NC}"
        fi
    done

    echo ""
    local total unique_users
    total=$(grep -c '"eventid":"cowrie.login' "$json_log" 2>/dev/null || echo 0)
    unique_users=$(grep -oP '"username":"\K[^"]+' "$json_log" 2>/dev/null | sort -u | wc -l)
    echo "Total attempts: ${total}  |  Unique usernames: ${unique_users}"
}

# ── Captured Downloads ──────────────────────────────────────────────────────
do_downloads() {
    echo -e "${BOLD}── Captured Downloads ──${NC}"
    echo ""

    if [[ ! -d "$COWRIE_DL_DIR" ]] || [[ -z "$(ls -A "$COWRIE_DL_DIR" 2>/dev/null)" ]]; then
        echo "  No files captured yet."
        return
    fi

    echo -e "  ${BOLD}SHA256                                                            Size${NC}"
    echo "  ──────────────────────────────────────────────────────────────── ────────"
    for f in "$COWRIE_DL_DIR"/*; do
        [[ -f "$f" ]] || continue
        local hash size
        hash=$(sha256sum "$f" | awk '{print $1}')
        size=$(du -h "$f" | awk '{print $1}')
        echo "  ${hash}  ${size}"
    done

    echo ""
    local count
    count=$(find "$COWRIE_DL_DIR" -type f 2>/dev/null | wc -l)
    echo "Total files captured: ${count}"
    echo -e "${YELLOW}WARNING: These files are likely malware. Handle with care.${NC}"
}

# ── Splunk Integration ──────────────────────────────────────────────────────
do_splunk() {
    local splunk_home="/opt/splunkforwarder"
    if [[ ! -d "$splunk_home" ]]; then
        splunk_home="/opt/splunk"
    fi
    if [[ ! -d "$splunk_home" ]]; then
        log_warn "Splunk/Splunk Forwarder not found at /opt/splunk or /opt/splunkforwarder."
        log_info "Install a Splunk forwarder first, then re-run this command."
        return
    fi

    log_info "Configuring Splunk to monitor Cowrie JSON logs..."

    local inputs_conf="${splunk_home}/etc/system/local/inputs.conf"
    if grep -q "cowrie.json" "$inputs_conf" 2>/dev/null; then
        log_warn "Splunk is already monitoring cowrie.json."
        return
    fi

    cat >> "$inputs_conf" <<SPLUNKCFG

[monitor://${COWRIE_LOG_DIR}/cowrie.json]
sourcetype = cowrie
index = main
SPLUNKCFG

    # Restart Splunk to pick up changes
    if [[ -x "${splunk_home}/bin/splunk" ]]; then
        "${splunk_home}/bin/splunk" restart >/dev/null 2>&1 || true
        log_info "Splunk restarted. Cowrie logs will appear with sourcetype=cowrie."
    fi
}

# ── Interactive Menu ────────────────────────────────────────────────────────
interactive_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}── Cowrie Honeypot Manager ──${NC}"
        echo ""
        echo "  1) Install Cowrie"
        echo "  2) Uninstall Cowrie"
        echo "  3) Status & Stats"
        echo "  4) Tail Live Logs"
        echo "  5) View Captured Sessions"
        echo "  6) View Captured Credentials"
        echo "  7) View Captured Downloads"
        echo "  8) Configure Splunk Forwarding"
        echo "  9) Quit"
        echo ""
        read -r -p "Choice [1-9]: " opt
        case "$opt" in
            1) do_install ;;
            2) do_uninstall ;;
            3) do_status ;;
            4) do_logs ;;
            5) do_sessions ;;
            6) do_creds ;;
            7) do_downloads ;;
            8) do_splunk ;;
            9) log_info "Exiting."; exit 0 ;;
            *) log_warn "Invalid choice." ;;
        esac
    done
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    check_root
    detect_pkg_manager

    case "${1:-}" in
        install)    do_install ;;
        uninstall)  do_uninstall ;;
        status)     do_status ;;
        logs)       do_logs ;;
        sessions)   do_sessions ;;
        creds)      do_creds ;;
        downloads)  do_downloads ;;
        splunk)     do_splunk ;;
        -h|--help)
            echo "Usage: $0 {install|uninstall|status|logs|sessions|creds|downloads|splunk}"
            ;;
        *)          interactive_menu ;;
    esac
}

main "$@"
