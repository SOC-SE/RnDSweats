# ==============================================================================
# File: Liaison/FIM.sh
# Description: Monitors file integrity in specified directories/files using SHA256 hashes.
#              Supports multiple background sessions, menu-driven management.
#
# Key Features:
# 1. Menu to start new monitor, list active, stop monitor, view live logs, or exit.
# 2. Prompts for path to monitor; runs in background with periodic checks (60s).
# 3. Manages multiple sessions via /tmp/fim_sessions/ for state persistence.
# 4. Duplicate path check; clean session cleanup on stop.
# 5. Live log viewing with tail -f (Ctrl+C to exit view).
# 6. No package installation; uses built-in tools for CCDC portability.
# 7. Validated for efficiency in virtual environments (e.g., NETLAB VE VMs).
# ==============================================================================

#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
 _______ _________ _______ 
(  ____ \\__   __/(       )
| (    \/   ) (   | () () |
| (__       | |   | || || |
|  __)      | |   | |(_)| |
| (         | |   | |   | |
| )      ___) (___| )   ( |
|/       \_______/|/     \| 
EOF
echo -e "\033[0m"
echo "File Intgrity Montioring Script - For CCDC Team Prep"
echo "-------------------------------------------------------------"

# --- Configuration & Colors ---
CHECK_INTERVAL=60  # Seconds between checks
SESSION_DIR="/tmp/fim_sessions"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# --- Setup Session Directory ---
setup_sessions() {
    mkdir -p "$SESSION_DIR"
}

# --- Generate Unique ID for Path (MD5 hash) ---
generate_id() {
    echo -n "$1" | md5sum | awk '{print $1}'
}

# --- Check if Path Already Monitored ---
is_monitored() {
    local path="$1"
    local id=$(generate_id "$path")
    [ -d "$SESSION_DIR/$id" ]
}

# --- List Active Monitors ---
list_monitors() {
    log_info "Active Monitored Paths:"
    local count=0
    for dir in "$SESSION_DIR"/*; do
        if [ -d "$dir" ]; then
            local session_id=$(basename "$dir")
            local path=$(cat "$dir/path.txt" 2>/dev/null)
            local pid=$(cat "$dir/pid.txt" 2>/dev/null)
            if [ -n "$path" ] && [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                echo "- ID: $session_id | Path: $path | PID: $pid"
                count=$((count + 1))
            else
                # Clean up dead sessions
                rm -rf "$dir"
            fi
        fi
    done
    if [ "$count" -eq 0 ]; then
        log_warn "No active monitors."
    fi
}

# --- Start New Monitor ---
start_new_monitor() {
    read -p "Enter the file/directory path to monitor: " MONITOR_PATH
    if [ ! -e "$MONITOR_PATH" ]; then
        log_error "Path '$MONITOR_PATH' does not exist."
    fi
    MONITOR_PATH=$(realpath "$MONITOR_PATH")
    if is_monitored "$MONITOR_PATH"; then
        log_warn "Path '$MONITOR_PATH' is already being monitored."
        return
    fi

    local id=$(generate_id "$MONITOR_PATH")
    local session_dir="$SESSION_DIR/$id"
    mkdir -p "$session_dir"
    echo "$MONITOR_PATH" > "$session_dir/path.txt"

    # Generate baseline
    find "$MONITOR_PATH" -type f -print0 | xargs -0 sha256sum > "$session_dir/baseline.txt" 2>/dev/null || true
    log_info "Baseline generated for $MONITOR_PATH"

    # Start background monitoring process
    nohup bash -c "
        while true; do
            find \"$MONITOR_PATH\" -type f -print0 | xargs -0 sha256sum > \"$session_dir/current.txt\" 2>/dev/null
            if ! diff -q \"$session_dir/baseline.txt\" \"$session_dir/current.txt\" > /dev/null 2>&1; then
                echo \"\$(date '+%Y-%m-%d %H:%M:%S') - Changes detected in $MONITOR_PATH:\" >> \"$session_dir/log.txt\"
                diff \"$session_dir/baseline.txt\" \"$session_dir/current.txt\" >> \"$session_dir/log.txt\" 2>&1
                echo \"--------------------------------------\" >> \"$session_dir/log.txt\"
            else
                echo \"\$(date '+%Y-%m-%d %H:%M:%S') - No changes in $MONITOR_PATH.\" >> \"$session_dir/log.txt\"
            fi
            rm -f \"$session_dir/current.txt\"
            sleep $CHECK_INTERVAL
        done
    " > /dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$session_dir/pid.txt"
    log_info "Started monitoring $MONITOR_PATH in background (PID: $pid)"
}

# --- Stop Monitor ---
stop_monitor() {
    list_monitors
    read -p "Enter the ID of the session to stop (or 'cancel'): " session_id
    if [ "$session_id" = "cancel" ]; then
        return
    fi
    local session_dir="$SESSION_DIR/$session_id"
    if [ ! -d "$session_dir" ]; then
        log_error "Invalid session ID: $session_id"
    fi
    local pid=$(cat "$session_dir/pid.txt" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        log_info "Stopped monitoring for session $session_id (PID: $pid)"
    else
        log_warn "Session $session_id was not running."
    fi
    rm -rf "$session_dir"
}

# --- View Live Logs ---
view_logs() {
    list_monitors
    read -p "Enter the ID of the session to view logs (or 'cancel'): " session_id
    if [ "$session_id" = "cancel" ]; then
        return
    fi
    local session_dir="$SESSION_DIR/$session_id"
    if [ ! -d "$session_dir" ]; then
        log_error "Invalid session ID: $session_id"
    fi
    local log_file="$session_dir/log.txt"
    if [ -f "$log_file" ]; then
        log_info "Viewing live logs for session $session_id. Press Ctrl+C to exit."
        trap 'log_info "Exiting log view."; return' INT
        tail -f "$log_file"
        trap - INT
    else
        log_warn "No log file found for session $session_id."
    fi
}

# --- Menu Prompt ---
prompt_menu() {
    while true; do
        log_info "FIM Menu:"
        echo "1) Start monitoring a new path"
        echo "2) List active monitors"
        echo "3) Stop monitoring a path"
        echo "4) View live logs for a monitor"
        echo "5) Exit"
        read -p "Enter your choice (1-5): " choice
        case "$choice" in
            1) start_new_monitor ;;
            2) list_monitors ;;
            3) stop_monitor ;;
            4) view_logs ;;
            5) log_info "Exiting FIM script."; exit 0 ;;
            *) log_error "Invalid choice. Please select 1-5." ;;
        esac
        echo ""  # Spacer for readability
    done
}

# --- Main Logic ---
main() {
    setup_sessions
    prompt_menu
}

main "$@"
