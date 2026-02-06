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
#   ./CowrieHoneypot.sh start         Start Cowrie service
#   ./CowrieHoneypot.sh stop          Stop Cowrie service
#   ./CowrieHoneypot.sh status        Show service status and recent activity
#   ./CowrieHoneypot.sh logs          Tail live JSON logs
#   ./CowrieHoneypot.sh sessions      Show recent captured sessions
#   ./CowrieHoneypot.sh creds         Show captured credentials
#   ./CowrieHoneypot.sh downloads     List captured files/malware
#   ./CowrieHoneypot.sh               Interactive menu
#
# ENVIRONMENT VARIABLES:
#   COWRIE_HOSTNAME    Fake hostname shown to attackers (default: actual hostname)

set -euo pipefail

# Resolve script directory once, before anything can change CWD
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ───────────────────────────────────────────────────────────
COWRIE_USER="cowrie"
COWRIE_HOME="/opt/cowrie"
COWRIE_REPO="https://github.com/cowrie/cowrie.git"
COWRIE_VENV="${COWRIE_HOME}/cowrie-env"
COWRIE_CFG="${COWRIE_HOME}/etc/cowrie.cfg"
COWRIE_LOG_DIR="${COWRIE_HOME}/var/log/cowrie"
COWRIE_DL_DIR="${COWRIE_HOME}/var/lib/cowrie/downloads"
COWRIE_TTY_DIR="${COWRIE_HOME}/var/lib/cowrie/tty"

# Listening ports
LISTEN_SSH_PORT=2222
LISTEN_TELNET_PORT=2223
LISTEN_ENABLED_TELNET="false"

# Hostname the fake shell presents to attackers (defaults to actual hostname)
FAKE_HOSTNAME="${COWRIE_HOSTNAME:-$(hostname -s)}"

# Minimum Python version Cowrie requires (major.minor)
COWRIE_MIN_PYTHON="3.10"

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

# Compare two version strings: returns 0 if $1 >= $2
version_gte() {
    local v1_major v1_minor v2_major v2_minor
    v1_major="${1%%.*}"; v1_minor="${1#*.}"
    v2_major="${2%%.*}"; v2_minor="${2#*.}"
    if (( v1_major > v2_major )); then return 0; fi
    if (( v1_major == v2_major && v1_minor >= v2_minor )); then return 0; fi
    return 1
}

# Find a Python >= COWRIE_MIN_PYTHON, installing one if necessary.
# Sets PYTHON_BIN to the usable interpreter path.
find_or_install_python() {
    # Check system python3 first
    if command -v python3 &>/dev/null; then
        local sys_ver
        sys_ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if version_gte "$sys_ver" "$COWRIE_MIN_PYTHON"; then
            PYTHON_BIN="python3"
            log_info "System Python ${sys_ver} meets requirement (>= ${COWRIE_MIN_PYTHON})."
            return
        fi
        log_warn "System Python is ${sys_ver}, but Cowrie requires >= ${COWRIE_MIN_PYTHON}."
    fi

    # Check for existing alternate installs (python3.12, python3.11, python3.10)
    local candidate
    for candidate in python3.12 python3.11 python3.10; do
        if command -v "$candidate" &>/dev/null; then
            local cand_ver
            cand_ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
            if version_gte "$cand_ver" "$COWRIE_MIN_PYTHON"; then
                PYTHON_BIN="$candidate"
                log_info "Found ${candidate} (${cand_ver}) - using it."
                return
            fi
        fi
    done

    # Need to install one
    log_info "Installing a compatible Python version..."
    case "$PKG_MANAGER" in
        apt)
            # Debian/Ubuntu: try python3.11 from deadsnakes or default repos
            $INSTALL_CMD python3.11 python3.11-venv python3.11-dev 2>&1 || \
            $INSTALL_CMD python3.10 python3.10-venv python3.10-dev 2>&1 || \
                log_fatal "Could not install Python >= ${COWRIE_MIN_PYTHON}. Install manually."
            ;;
        dnf|yum)
            # RHEL/Oracle/Rocky/Fedora: python3.12 or python3.11 from appstream
            $INSTALL_CMD python3.12 python3.12-devel python3.12-pip 2>&1 || \
            $INSTALL_CMD python3.11 python3.11-devel python3.11-pip 2>&1 || \
                log_fatal "Could not install Python >= ${COWRIE_MIN_PYTHON}. Install manually."
            ;;
        *)
            log_fatal "Cannot auto-install Python >= ${COWRIE_MIN_PYTHON} on this OS. Install manually."
            ;;
    esac

    # Re-scan for the newly installed interpreter
    for candidate in python3.12 python3.11 python3.10; do
        if command -v "$candidate" &>/dev/null; then
            PYTHON_BIN="$candidate"
            log_info "Installed and using ${candidate}."
            return
        fi
    done

    log_fatal "Failed to find a Python >= ${COWRIE_MIN_PYTHON} after installation attempt."
}

# ── Install ─────────────────────────────────────────────────────────────────
install_dependencies() {
    log_info "Installing system dependencies..."
    $UPDATE_CMD >/dev/null 2>&1

    local deps_common="git python3 python3-pip gcc make"
    local deps_extra=""

    case "$PKG_MANAGER" in
        apt)
            deps_common="$deps_common python3-venv python3-dev libssl-dev libffi-dev"
            deps_extra="build-essential libpython3-dev"
            ;;
        dnf|yum)
            deps_common="$deps_common python3-devel openssl-devel libffi-devel"
            deps_extra="redhat-rpm-config"
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
    if ! git clone --quiet --depth 1 "$COWRIE_REPO" "$tmp_dir/cowrie" 2>/dev/null; then
        rm -rf "$tmp_dir"
        # Fallback to vendored copy
        local vendor_src
        vendor_src="${SCRIPT_DIR}/../../vendor/cowrie/source"
        if [[ -d "$vendor_src/src" ]]; then
            log_info "Git clone failed. Using vendored local copy..."
            cp -a "$vendor_src/." "$COWRIE_HOME/"
        else
            log_fatal "Failed to clone Cowrie repository and no vendor copy found."
        fi
    else
        # Verify clone succeeded
        if [[ ! -d "$tmp_dir/cowrie/src" ]]; then
            rm -rf "$tmp_dir"
            log_fatal "Failed to clone Cowrie repository. Check network connectivity."
        fi
        cp -a "$tmp_dir/cowrie/." "$COWRIE_HOME/"
        rm -rf "$tmp_dir"
    fi
    chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_HOME"
    log_info "Cowrie cloned to ${COWRIE_HOME}."
}

setup_virtualenv() {
    log_info "Setting up Python virtual environment (using ${PYTHON_BIN})..."

    # Create venv with the correct Python interpreter
    if [[ ! -d "$COWRIE_VENV" ]]; then
        sudo -u "$COWRIE_USER" "$PYTHON_BIN" -m venv "$COWRIE_VENV"
    else
        # Verify existing venv uses a compatible Python
        local venv_ver
        venv_ver=$("$COWRIE_VENV/bin/python3" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        if ! version_gte "$venv_ver" "$COWRIE_MIN_PYTHON"; then
            log_warn "Existing venv uses Python ${venv_ver}. Recreating with ${PYTHON_BIN}..."
            rm -rf "$COWRIE_VENV"
            sudo -u "$COWRIE_USER" "$PYTHON_BIN" -m venv "$COWRIE_VENV"
        fi
    fi

    # Locate vendored wheels — search upward from script dir for vendor/cowrie/wheels
    local VENDOR_WHEELS=""
    local _search_dir="$SCRIPT_DIR"
    while [[ "$_search_dir" != "/" ]]; do
        if [[ -d "${_search_dir}/vendor/cowrie/wheels" ]]; then
            VENDOR_WHEELS="${_search_dir}/vendor/cowrie/wheels"
            break
        fi
        _search_dir="$(dirname "$_search_dir")"
    done

    # Quick connectivity check — avoid wasting minutes on pip retries if PyPI is unreachable
    local USE_VENDOR=false
    log_info "Checking PyPI connectivity..."
    if curl -s --max-time 10 -o /dev/null https://pypi.org/simple/pip/; then
        log_info "PyPI is reachable."
    elif [[ -n "$VENDOR_WHEELS" ]]; then
        log_warn "PyPI unreachable (timeout). Using vendored wheels from ${VENDOR_WHEELS}..."
        # Copy wheels to a temp dir the cowrie user can access (the repo may be
        # under a home directory with 700 permissions that cowrie can't traverse)
        local VENDOR_TMP
        VENDOR_TMP=$(mktemp -d)
        cp "$VENDOR_WHEELS"/*.whl "$VENDOR_TMP/"
        chown -R "$COWRIE_USER" "$VENDOR_TMP"
        VENDOR_WHEELS="$VENDOR_TMP"
        USE_VENDOR=true
    else
        log_fatal "PyPI unreachable and no vendored wheels found. Searched upward from ${SCRIPT_DIR}."
    fi

    if [[ "$USE_VENDOR" == "true" ]]; then
        log_info "Upgrading pip/setuptools/wheel from vendored wheels..."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --no-index --find-links "$VENDOR_WHEELS" --upgrade pip setuptools wheel \
            || log_fatal "Failed to upgrade pip/setuptools/wheel from vendored wheels."

        log_info "Installing Cowrie requirements from vendored wheels..."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --no-index --find-links "$VENDOR_WHEELS" -r "${COWRIE_HOME}/requirements.txt" \
            || log_fatal "Failed to install requirements from vendored wheels."

        # Install cowrie itself — need setuptools-scm for dynamic versioning
        log_info "Installing Cowrie package..."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --no-index --find-links "$VENDOR_WHEELS" setuptools-scm \
            || log_fatal "Failed to install setuptools-scm from vendored wheels."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --no-build-isolation --no-deps -e "${COWRIE_HOME}" \
            || log_fatal "Failed to install Cowrie package."
    else
        local PIP_OPTS="--timeout 120"

        log_info "Upgrading pip/setuptools/wheel..."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install $PIP_OPTS --upgrade pip setuptools wheel \
            || log_fatal "Failed to upgrade pip/setuptools/wheel."

        log_info "Installing Cowrie requirements (this may take a few minutes)..."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install $PIP_OPTS -r "${COWRIE_HOME}/requirements.txt" \
            || log_fatal "Failed to install requirements.txt."

        log_info "Installing Cowrie package..."
        sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install $PIP_OPTS -e "${COWRIE_HOME}" \
            || log_fatal "Failed to install Cowrie package."
    fi

    # Verify the Twisted plugin is discoverable
    if ! "$COWRIE_VENV/bin/python3" -c "import cowrie" 2>/dev/null; then
        log_fatal "Cowrie module not importable after install. Check pip output above."
    fi

    # Fix SELinux contexts so systemd can exec twistd (Oracle/RHEL)
    if command -v restorecon &>/dev/null; then
        restorecon -R "$COWRIE_VENV/bin/" 2>/dev/null || true
    fi

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
# Cowrie Configuration
# Generated by CowrieHoneypot.sh

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

# --- SSH Settings ---
[ssh]
enabled = true
listen_endpoints = tcp:${LISTEN_SSH_PORT}:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6

# --- Telnet Settings ---
[telnet]
enabled = ${LISTEN_ENABLED_TELNET}
listen_endpoints = tcp:${LISTEN_TELNET_PORT}:interface=0.0.0.0

# --- Logging: JSON (primary, for SIEM/Splunk) ---
[output_jsonlog]
enabled = true
logfile = ${COWRIE_LOG_DIR}/cowrie.json

# --- Logging: Text (human-readable) ---
[output_textlog]
enabled = true
logfile = ${COWRIE_LOG_DIR}/cowrie.log
COWRIECFG

    chown "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_CFG"

    # Ensure log, data, and runtime directories exist
    mkdir -p "$COWRIE_LOG_DIR" "$COWRIE_DL_DIR" "$COWRIE_TTY_DIR" "${COWRIE_HOME}/var/run"
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
Environment=COWRIE_STDOUT=yes
WorkingDirectory=${COWRIE_HOME}
ExecStartPre=+${COWRIE_HOME}/bin/cowrie-firewall.sh
ExecStart=${COWRIE_VENV}/bin/twistd --nodaemon --umask=0022 --pidfile= cowrie
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=${COWRIE_HOME}/var

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    log_info "Systemd unit created."
}

setup_firewall() {
    log_info "Configuring firewall rules..."

    if ! command -v iptables &>/dev/null; then
        log_warn "iptables not found. Skipping firewall configuration."
        return
    fi

    # Allow Cowrie's listen port — use -I (insert) so the rule goes before any
    # REJECT/DROP rules that hardening scripts may have appended to INPUT
    if ! iptables -C INPUT -p tcp --dport "$LISTEN_SSH_PORT" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport "$LISTEN_SSH_PORT" -j ACCEPT
        log_info "Allowed inbound TCP/${LISTEN_SSH_PORT} (Cowrie)."
    fi

    if [[ "$LISTEN_ENABLED_TELNET" == "true" ]]; then
        if ! iptables -C INPUT -p tcp --dport "$LISTEN_TELNET_PORT" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p tcp --dport "$LISTEN_TELNET_PORT" -j ACCEPT
            log_info "Allowed inbound TCP/${LISTEN_TELNET_PORT} (Cowrie telnet)."
        fi
    fi

    # Redirect external port 22 -> Cowrie
    # Assumes sshd is already removed/disabled; PREROUTING only affects external traffic
    if ! iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$LISTEN_SSH_PORT" 2>/dev/null; then
        iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$LISTEN_SSH_PORT"
        log_info "Redirecting external port 22 -> ${LISTEN_SSH_PORT} (Cowrie)."
    fi

    # Create a helper script that systemd runs on every Cowrie start (ExecStartPre).
    # This makes the firewall self-healing: if the hardening script is re-run,
    # nft is flushed, or rules are lost on reboot, Cowrie re-applies them automatically.
    local fw_script="${COWRIE_HOME}/bin/cowrie-firewall.sh"
    mkdir -p "$(dirname "$fw_script")"
    cat > "$fw_script" <<FWEOF
#!/bin/bash
# Auto-generated by CowrieHoneypot.sh — ensures iptables rules exist before Cowrie starts.
# Run by systemd ExecStartPre (as root via + prefix).

IPTABLES=\$(command -v iptables 2>/dev/null) || exit 0

# INPUT: accept traffic to Cowrie's listen port (insert before REJECT/DROP)
\$IPTABLES -C INPUT -p tcp --dport ${LISTEN_SSH_PORT} -j ACCEPT 2>/dev/null || \\
    \$IPTABLES -I INPUT -p tcp --dport ${LISTEN_SSH_PORT} -j ACCEPT

# NAT PREROUTING: redirect external port 22 -> Cowrie
\$IPTABLES -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port ${LISTEN_SSH_PORT} 2>/dev/null || \\
    \$IPTABLES -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port ${LISTEN_SSH_PORT}
FWEOF

    if [[ "$LISTEN_ENABLED_TELNET" == "true" ]]; then
        cat >> "$fw_script" <<FWEOF

# INPUT: accept traffic to Cowrie's telnet port
\$IPTABLES -C INPUT -p tcp --dport ${LISTEN_TELNET_PORT} -j ACCEPT 2>/dev/null || \\
    \$IPTABLES -I INPUT -p tcp --dport ${LISTEN_TELNET_PORT} -j ACCEPT
FWEOF
    fi

    echo "" >> "$fw_script"
    echo "exit 0" >> "$fw_script"
    chmod 755 "$fw_script"
    # Fix SELinux context so systemd can exec the script (Fedora/Oracle/RHEL)
    if command -v restorecon &>/dev/null; then
        restorecon "$fw_script" 2>/dev/null || true
    fi
    log_info "Firewall helper script written to ${fw_script}."

    # Persist iptables rules across reboots
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
        log_info "iptables rules saved (netfilter-persistent)."
    elif [[ -f /etc/sysconfig/iptables ]]; then
        iptables-save > /etc/sysconfig/iptables
        log_info "iptables rules saved (/etc/sysconfig/iptables)."
    else
        log_warn "Could not persist iptables rules. Save manually or install iptables-persistent."
    fi

    log_info "Firewall rules configured."
}

start_cowrie() {
    systemctl enable cowrie >/dev/null 2>&1
    systemctl start cowrie

    # Wait for Twisted reactor to start
    sleep 5
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
    find_or_install_python
    create_cowrie_user
    clone_cowrie
    setup_virtualenv
    configure_cowrie
    create_systemd_unit
    setup_firewall
    start_cowrie

    echo ""
    echo -e "${BOLD}===================================================${NC}"
    echo -e "${GREEN} Cowrie honeypot installed and running${NC}"
    echo -e "${BOLD}===================================================${NC}"
    echo -e " Port 22:         ${CYAN}redirected -> Cowrie (${LISTEN_SSH_PORT})${NC}"
    [[ "$LISTEN_ENABLED_TELNET" == "true" ]] && \
        echo -e " Telnet listener: ${CYAN}port ${LISTEN_TELNET_PORT}${NC}"
    echo -e " JSON logs:       ${CYAN}${COWRIE_LOG_DIR}/cowrie.json${NC}"
    echo -e " Text logs:       ${CYAN}${COWRIE_LOG_DIR}/cowrie.log${NC}"
    echo -e " Downloads:       ${CYAN}${COWRIE_DL_DIR}/${NC}"
    echo -e " Sessions:        ${CYAN}${COWRIE_TTY_DIR}/${NC}"
    echo ""
}

# ── Start / Stop ───────────────────────────────────────────────────────────
do_start() {
    if ! systemctl is-enabled --quiet cowrie 2>/dev/null; then
        log_fatal "Cowrie is not installed. Run '$0 install' first."
    fi
    log_info "Starting Cowrie..."
    systemctl start cowrie
    sleep 3
    if systemctl is-active --quiet cowrie; then
        log_info "Cowrie is running."
    else
        log_error "Cowrie failed to start. Check: journalctl -u cowrie -n 50"
    fi
}

do_stop() {
    log_info "Stopping Cowrie..."
    systemctl stop cowrie 2>/dev/null || true
    log_info "Cowrie stopped."
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

    # Remove firewall rules
    iptables -D INPUT -p tcp --dport "$LISTEN_SSH_PORT" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$LISTEN_SSH_PORT" 2>/dev/null || true

    log_info "Cowrie uninstalled."
}

# ── Status ──────────────────────────────────────────────────────────────────
do_status() {
    echo -e "${BOLD}-- Cowrie Status --${NC}"
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

    echo -e "${BOLD}-- Recent Sessions --${NC}"
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

    echo -e "${BOLD}-- Captured Credentials --${NC}"
    echo ""
    echo -e "  ${BOLD}Source IP         Username         Password${NC}"
    echo "  ---------------- ---------------- ----------------"

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
    echo -e "${BOLD}-- Captured Downloads --${NC}"
    echo ""

    if [[ ! -d "$COWRIE_DL_DIR" ]] || [[ -z "$(ls -A "$COWRIE_DL_DIR" 2>/dev/null)" ]]; then
        echo "  No files captured yet."
        return
    fi

    echo -e "  ${BOLD}SHA256                                                            Size${NC}"
    echo "  ---------------------------------------------------------------- --------"
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

# ── Interactive Menu ────────────────────────────────────────────────────────
interactive_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}-- Cowrie Honeypot Manager --${NC}"
        echo ""
        echo "  1) Install Cowrie"
        echo "  2) Uninstall Cowrie"
        echo "  3) Start Cowrie"
        echo "  4) Stop Cowrie"
        echo "  5) Status & Stats"
        echo "  6) Tail Live Logs"
        echo "  7) View Captured Sessions"
        echo "  8) View Captured Credentials"
        echo "  9) View Captured Downloads"
        echo "  0) Quit"
        echo ""
        read -r -p "Choice [0-9]: " opt
        case "$opt" in
            1) do_install ;;
            2) do_uninstall ;;
            3) do_start ;;
            4) do_stop ;;
            5) do_status ;;
            6) do_logs ;;
            7) do_sessions ;;
            8) do_creds ;;
            9) do_downloads ;;
            0) log_info "Exiting."; exit 0 ;;
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
        start)      do_start ;;
        stop)       do_stop ;;
        status)     do_status ;;
        logs)       do_logs ;;
        sessions)   do_sessions ;;
        creds)      do_creds ;;
        downloads)  do_downloads ;;
        -h|--help)
            echo "Usage: $0 {install|uninstall|start|stop|status|logs|sessions|creds|downloads}"
            ;;
        *)          interactive_menu ;;
    esac
}

main "$@"
