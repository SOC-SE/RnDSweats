#!/bin/bash
# ==============================================================================
# Script Name: ttyMon.sh
# Description: TTY session monitor that runs as a systemd service.
#              Detects new login sessions, logs source details, and alerts
#              via syslog. Persists across reboots.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./ttyMon.sh install     Install and start the systemd service
#   ./ttyMon.sh uninstall   Stop and remove the service
#   ./ttyMon.sh status      Show service status
#   ./ttyMon.sh run         Run the monitor directly (used by systemd)
#
# What It Does:
#   - Polls for active TTY/PTY sessions every 5 seconds
#   - Detects new sessions (not seen in previous poll)
#   - Logs: user, TTY, source IP/host, login time
#   - Writes to /var/log/syst/ttymon.log and syslog
#   - Skips the session that installed the service (configurable)
#
# Supported Systems:
#   - Any Linux with systemd and the 'w' command
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   3 - Permission denied
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="ttymon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/syst/ttymon.log"
STATE_FILE="/var/run/ttymon.state"
POLL_INTERVAL=5

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null
    logger -t ttymon "$1" 2>/dev/null
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        exit 3
    fi
}

# --- Install Service ---
do_install() {
    check_root

    # Get absolute path to this script
    local script_path
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    echo -e "${GREEN}[INFO]${NC} Installing ttymon service..."

    # Create log file
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    # Create systemd service
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=TTY Session Monitor - CCDC
After=network.target
Documentation=CCDC Development Toolkit

[Service]
Type=simple
ExecStart=/bin/bash $script_path run
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    echo -e "${GREEN}[INFO]${NC} ttymon service installed and started"
    echo -e "${GREEN}[INFO]${NC} Log file: $LOG_FILE"
    echo -e "${GREEN}[INFO]${NC} Check status: systemctl status ttymon"
}

# --- Uninstall Service ---
do_uninstall() {
    check_root
    echo -e "${YELLOW}[INFO]${NC} Removing ttymon service..."

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -f "$STATE_FILE"
    systemctl daemon-reload

    echo -e "${GREEN}[INFO]${NC} ttymon service removed"
    echo -e "${GREEN}[INFO]${NC} Log file preserved at: $LOG_FILE"
}

# --- Show Status ---
do_status() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "${GREEN}[RUNNING]${NC} ttymon service is active"
    else
        echo -e "${RED}[STOPPED]${NC} ttymon service is not running"
    fi
    systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || true
    echo ""
    echo "Recent log entries:"
    tail -20 "$LOG_FILE" 2>/dev/null || echo "(no log file)"
}

# --- Get current sessions as a sorted unique list ---
# Format per line: USER TTY FROM LOGIN_TIME
get_sessions() {
    # w -h gives: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
    # We extract USER, TTY, FROM, LOGIN@
    w -h 2>/dev/null | awk '{print $1, $2, $3, $4}' | sort -u
}

# --- Run Monitor (called by systemd) ---
do_run() {
    log_msg "ttymon started — monitoring TTY/PTY sessions"

    # Initialize state with current sessions
    get_sessions > "$STATE_FILE"
    log_msg "Initial sessions: $(wc -l < "$STATE_FILE") active"

    while true; do
        sleep "$POLL_INTERVAL"

        local current_sessions
        current_sessions=$(get_sessions)

        # Compare: find lines in current that are NOT in the state file (new sessions)
        local new_sessions
        new_sessions=$(comm -23 <(echo "$current_sessions" | sort) <(sort "$STATE_FILE" 2>/dev/null) 2>/dev/null || true)

        if [[ -n "$new_sessions" ]]; then
            while IFS= read -r session; do
                local user tty from login_time
                user=$(echo "$session" | awk '{print $1}')
                tty=$(echo "$session" | awk '{print $2}')
                from=$(echo "$session" | awk '{print $3}')
                login_time=$(echo "$session" | awk '{print $4}')

                # Determine source description
                local source_desc
                if [[ "$from" == "-" || -z "$from" ]]; then
                    source_desc="local console"
                else
                    source_desc="$from"
                fi

                local alert_msg="NEW SESSION: user=$user tty=$tty from=$source_desc login=$login_time"
                log_msg "$alert_msg"

                # Also alert via wall if this looks like a remote session
                if [[ "$from" != "-" && -n "$from" ]]; then
                    echo "TTYMON ALERT: $alert_msg" | wall 2>/dev/null || true
                fi
            done <<< "$new_sessions"
        fi

        # Check for closed sessions
        local closed_sessions
        closed_sessions=$(comm -23 <(sort "$STATE_FILE" 2>/dev/null) <(echo "$current_sessions" | sort) 2>/dev/null || true)

        if [[ -n "$closed_sessions" ]]; then
            while IFS= read -r session; do
                local user tty from
                user=$(echo "$session" | awk '{print $1}')
                tty=$(echo "$session" | awk '{print $2}')
                from=$(echo "$session" | awk '{print $3}')
                log_msg "SESSION CLOSED: user=$user tty=$tty from=${from:--}"
            done <<< "$closed_sessions"
        fi

        # Update state
        echo "$current_sessions" > "$STATE_FILE"
    done
}

# --- Main ---
case "${1:-}" in
    install)
        do_install
        ;;
    uninstall|remove)
        do_uninstall
        ;;
    status)
        do_status
        ;;
    run)
        do_run
        ;;
    *)
        echo "Usage: $SCRIPT_NAME {install|uninstall|status|run}"
        echo ""
        echo "  install    Install and start the systemd service"
        echo "  uninstall  Stop and remove the service"
        echo "  status     Show service status and recent logs"
        echo "  run        Run monitor directly (used by systemd)"
        exit 1
        ;;
esac

exit 0
