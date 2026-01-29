#!/bin/bash
# ==============================================================================
# Script Name: webFIM.sh
# Description: Lightweight file integrity monitor for web directories.
#              Runs as a systemd service, logs changes to syslog and local log.
#              Supplements Wazuh FIM with immediate local alerting.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./webFIM.sh install [options]   Install and start the systemd service
#   ./webFIM.sh uninstall           Stop and remove the service
#   ./webFIM.sh status              Show service status
#   ./webFIM.sh init [options]      Create initial baseline (run once first)
#   ./webFIM.sh check [options]     Run a single check against baseline
#   ./webFIM.sh run [options]       Run monitor loop (used by systemd)
#
# Options:
#   -p, --paths PATH    Comma-separated paths to monitor (default: /var/www)
#   -i, --interval SEC  Check interval in seconds (default: 30)
#   -b, --baseline FILE Baseline file path (default: /var/lib/webfim/baseline.sha256)
#
# What It Monitors:
#   - File additions, deletions, and modifications (SHA-256)
#   - Logs to /var/log/syst/webfim.log and syslog
#   - Alerts via wall for critical changes
#
# Supported Systems:
#   - Any Linux with systemd, sha256sum, and find
#
# Exit Codes:
#   0 - Success / no changes
#   1 - Changes detected
#   3 - Permission denied
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="webfim"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/syst/webfim.log"
BASELINE_DIR="/var/lib/webfim"
BASELINE_FILE="$BASELINE_DIR/baseline.sha256"
MONITOR_PATHS="/var/www"
CHECK_INTERVAL=30

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_msg() {
    local level="$1"
    local msg="$2"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "$ts [$level] $msg" >> "$LOG_FILE" 2>/dev/null
    logger -t webfim -p "local0.${level,,}" "$msg" 2>/dev/null
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        exit 3
    fi
}

# --- Parse Options (after action) ---
parse_opts() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--paths)
                MONITOR_PATHS="$2"
                shift 2
                ;;
            -i|--interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            -b|--baseline)
                BASELINE_FILE="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
}

# --- Generate checksums for all files in monitored paths ---
generate_checksums() {
    local paths
    IFS=',' read -ra paths <<< "$MONITOR_PATHS"

    for path in "${paths[@]}"; do
        path=$(echo "$path" | xargs)  # trim whitespace
        if [[ -d "$path" ]]; then
            find "$path" -type f \
                ! -name "*.swp" \
                ! -name "*~" \
                ! -name "*.tmp" \
                ! -path "*/\.*" \
                -exec sha256sum {} \; 2>/dev/null
        elif [[ -f "$path" ]]; then
            sha256sum "$path" 2>/dev/null
        fi
    done | sort -k2
}

# --- Create Baseline ---
do_init() {
    check_root
    parse_opts "$@"

    mkdir -p "$BASELINE_DIR"
    chmod 700 "$BASELINE_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    echo -e "${GREEN}[INFO]${NC} Creating baseline for: $MONITOR_PATHS"
    generate_checksums > "$BASELINE_FILE"
    chmod 600 "$BASELINE_FILE"

    local count
    count=$(wc -l < "$BASELINE_FILE")
    echo -e "${GREEN}[INFO]${NC} Baseline created: $count files tracked"
    echo -e "${GREEN}[INFO]${NC} Baseline file: $BASELINE_FILE"
    log_msg "INFO" "Baseline created: $count files from $MONITOR_PATHS"
}

# --- Single Check ---
do_check() {
    parse_opts "$@"

    if [[ ! -f "$BASELINE_FILE" ]]; then
        echo -e "${RED}[ERROR]${NC} No baseline found. Run: $SCRIPT_NAME init"
        return 1
    fi

    local current_file
    current_file=$(mktemp)
    generate_checksums > "$current_file"

    local changes=0

    # Find added files (in current but not in baseline)
    local added
    added=$(comm -13 <(awk '{print $2}' "$BASELINE_FILE" | sort) <(awk '{print $2}' "$current_file" | sort) 2>/dev/null || true)
    if [[ -n "$added" ]]; then
        while IFS= read -r file; do
            log_msg "WARNING" "FILE ADDED: $file"
            echo -e "${YELLOW}[ADDED]${NC} $file"
            ((changes++))
        done <<< "$added"
    fi

    # Find removed files (in baseline but not in current)
    local removed
    removed=$(comm -23 <(awk '{print $2}' "$BASELINE_FILE" | sort) <(awk '{print $2}' "$current_file" | sort) 2>/dev/null || true)
    if [[ -n "$removed" ]]; then
        while IFS= read -r file; do
            log_msg "WARNING" "FILE REMOVED: $file"
            echo -e "${RED}[REMOVED]${NC} $file"
            ((changes++))
        done <<< "$removed"
    fi

    # Find modified files (same path, different hash)
    local modified
    modified=$(diff <(sort -k2 "$BASELINE_FILE") <(sort -k2 "$current_file") 2>/dev/null | grep "^[<>]" || true)
    # More precise: compare hashes for files that exist in both
    local common_files
    common_files=$(comm -12 <(awk '{print $2}' "$BASELINE_FILE" | sort) <(awk '{print $2}' "$current_file" | sort) 2>/dev/null || true)
    if [[ -n "$common_files" ]]; then
        while IFS= read -r file; do
            local old_hash new_hash
            old_hash=$(grep -F " $file" "$BASELINE_FILE" 2>/dev/null | awk '{print $1}' | head -1)
            new_hash=$(grep -F " $file" "$current_file" 2>/dev/null | awk '{print $1}' | head -1)
            if [[ "$old_hash" != "$new_hash" && -n "$old_hash" && -n "$new_hash" ]]; then
                log_msg "CRIT" "FILE MODIFIED: $file (old=$old_hash new=$new_hash)"
                echo -e "${RED}[MODIFIED]${NC} $file"
                ((changes++))
            fi
        done <<< "$common_files"
    fi

    rm -f "$current_file"

    if [[ $changes -eq 0 ]]; then
        log_msg "INFO" "Integrity check: no changes detected"
        echo -e "${GREEN}[OK]${NC} No changes detected"
        return 0
    else
        log_msg "WARNING" "Integrity check: $changes changes detected"
        echo "WEBFIM ALERT: $changes file changes detected in $MONITOR_PATHS" | wall 2>/dev/null || true
        return 1
    fi
}

# --- Run Loop (called by systemd) ---
do_run() {
    parse_opts "$@"
    log_msg "INFO" "webfim started — monitoring $MONITOR_PATHS every ${CHECK_INTERVAL}s"

    # Auto-init if no baseline exists
    if [[ ! -f "$BASELINE_FILE" ]]; then
        log_msg "INFO" "No baseline found, creating initial baseline"
        mkdir -p "$BASELINE_DIR"
        chmod 700 "$BASELINE_DIR"
        generate_checksums > "$BASELINE_FILE"
        chmod 600 "$BASELINE_FILE"
        log_msg "INFO" "Baseline created: $(wc -l < "$BASELINE_FILE") files"
    fi

    while true; do
        sleep "$CHECK_INTERVAL"

        local current_file
        current_file=$(mktemp)
        generate_checksums > "$current_file"

        local changes=0

        # Added files
        local added
        added=$(comm -13 <(awk '{print $2}' "$BASELINE_FILE" | sort) <(awk '{print $2}' "$current_file" | sort) 2>/dev/null || true)
        if [[ -n "$added" ]]; then
            while IFS= read -r file; do
                log_msg "WARNING" "FILE ADDED: $file"
                ((changes++))
            done <<< "$added"
        fi

        # Removed files
        local removed
        removed=$(comm -23 <(awk '{print $2}' "$BASELINE_FILE" | sort) <(awk '{print $2}' "$current_file" | sort) 2>/dev/null || true)
        if [[ -n "$removed" ]]; then
            while IFS= read -r file; do
                log_msg "WARNING" "FILE REMOVED: $file"
                ((changes++))
            done <<< "$removed"
        fi

        # Modified files
        local common_files
        common_files=$(comm -12 <(awk '{print $2}' "$BASELINE_FILE" | sort) <(awk '{print $2}' "$current_file" | sort) 2>/dev/null || true)
        if [[ -n "$common_files" ]]; then
            while IFS= read -r file; do
                local old_hash new_hash
                old_hash=$(grep -F " $file" "$BASELINE_FILE" 2>/dev/null | awk '{print $1}' | head -1)
                new_hash=$(grep -F " $file" "$current_file" 2>/dev/null | awk '{print $1}' | head -1)
                if [[ "$old_hash" != "$new_hash" && -n "$old_hash" && -n "$new_hash" ]]; then
                    log_msg "CRIT" "FILE MODIFIED: $file"
                    ((changes++))
                fi
            done <<< "$common_files"
        fi

        if [[ $changes -gt 0 ]]; then
            log_msg "WARNING" "Cycle complete: $changes changes detected"
            echo "WEBFIM ALERT: $changes file changes in $MONITOR_PATHS" | wall 2>/dev/null || true
        fi

        rm -f "$current_file"
    done
}

# --- Install Service ---
do_install() {
    check_root
    parse_opts "$@"

    local script_path
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    echo -e "${GREEN}[INFO]${NC} Installing webfim service..."

    # Create baseline if it doesn't exist
    if [[ ! -f "$BASELINE_FILE" ]]; then
        do_init "$@"
    fi

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Web File Integrity Monitor - CCDC
After=network.target
Documentation=CCDC Development Toolkit

[Service]
Type=simple
ExecStart=/bin/bash $script_path run -p $MONITOR_PATHS -i $CHECK_INTERVAL -b $BASELINE_FILE
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    echo -e "${GREEN}[INFO]${NC} webfim service installed and started"
    echo -e "${GREEN}[INFO]${NC} Monitoring: $MONITOR_PATHS"
    echo -e "${GREEN}[INFO]${NC} Interval: ${CHECK_INTERVAL}s"
    echo -e "${GREEN}[INFO]${NC} Log: $LOG_FILE"
}

# --- Uninstall ---
do_uninstall() {
    check_root
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${GREEN}[INFO]${NC} webfim service removed"
    echo -e "${GREEN}[INFO]${NC} Baseline and logs preserved"
}

# --- Status ---
do_status() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "${GREEN}[RUNNING]${NC} webfim service is active"
    else
        echo -e "${RED}[STOPPED]${NC} webfim service is not running"
    fi
    systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || true
    echo ""
    echo "Baseline: $BASELINE_FILE ($(wc -l < "$BASELINE_FILE" 2>/dev/null || echo 0) files)"
    echo ""
    echo "Recent log entries:"
    tail -20 "$LOG_FILE" 2>/dev/null || echo "(no log file)"
}

# --- Main ---
ACTION="${1:-}"
shift 2>/dev/null || true

case "$ACTION" in
    install)   do_install "$@" ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    init)      do_init "$@" ;;
    check)     do_check "$@" ;;
    run)       do_run "$@" ;;
    *)
        echo "Usage: $SCRIPT_NAME {install|uninstall|status|init|check|run} [options]"
        echo ""
        echo "Actions:"
        echo "  install    Install and start the systemd service"
        echo "  uninstall  Stop and remove the service"
        echo "  status     Show service status"
        echo "  init       Create initial baseline"
        echo "  check      Run a single integrity check"
        echo "  run        Run monitor loop (used by systemd)"
        echo ""
        echo "Options:"
        echo "  -p, --paths PATH      Comma-separated paths (default: /var/www)"
        echo "  -i, --interval SEC    Check interval in seconds (default: 30)"
        echo "  -b, --baseline FILE   Baseline file path"
        exit 1
        ;;
esac

exit 0
