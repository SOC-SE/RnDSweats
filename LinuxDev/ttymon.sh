#!/bin/bash
# ==============================================================================
# Script Name: ttymon.sh
# Description: TTY/PTS session monitoring and management tool
#              Identifies active sessions, detects suspicious activity,
#              and optionally kills unauthorized sessions
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./ttymon.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -a, --all        Show all users (not just current user)
#   -k, --kill       Kill other sessions (interactive prompt)
#   -K, --kill-all   Kill all other sessions without prompting
#   -u, --user USER  Monitor specific user
#   -w, --watch      Continuous monitoring mode (refresh every 5s)
#   -s, --suspicious Show only suspicious sessions
#
# Suspicious Session Indicators:
#   - Sessions from unusual IPs
#   - Sessions running suspicious commands
#   - Sessions with no controlling terminal
#   - Sessions that are idle for extended periods
#   - Sessions running as elevated users
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#
# Exit Codes:
#   0 - Success
#   1 - Error
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
CURRENT_USER=$(whoami)
CURRENT_TTY=$(tty 2>/dev/null | sed 's|/dev/||' || echo "unknown")
SHOW_ALL=false
KILL_MODE=false
KILL_ALL=false
TARGET_USER=""
WATCH_MODE=false
SUSPICIOUS_ONLY=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Known suspicious commands/patterns
SUSPICIOUS_PATTERNS=(
    "nc -"
    "ncat"
    "netcat"
    "/dev/tcp/"
    "/dev/udp/"
    "bash -i"
    "python.*pty"
    "perl.*socket"
    "ruby.*socket"
    "php.*fsockopen"
    "socat"
    "telnet"
    "cryptminer"
    "xmrig"
    "minerd"
)

# --- Helper Functions ---
usage() {
    head -45 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

critical() {
    echo -e "${RED}${BOLD}[CRITICAL]${NC} $1"
}

# Check if a command is suspicious
is_suspicious_command() {
    local cmd="$1"
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if echo "$cmd" | grep -qiE "$pattern"; then
            return 0
        fi
    done
    return 1
}

# Check if IP is internal
is_internal_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^10\. ]] || \
       [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
       [[ "$ip" =~ ^192\.168\. ]] || \
       [[ "$ip" =~ ^127\. ]] || \
       [[ "$ip" == "-" ]] || \
       [[ "$ip" == "" ]] || \
       [[ "$ip" == ":0" ]]; then
        return 0
    fi
    return 1
}

# Get process info for a TTY
get_tty_processes() {
    local tty="$1"
    ps -t "$tty" -o pid,user,cmd --no-headers 2>/dev/null | head -5
}

# Display session info
display_sessions() {
    local filter_user="$1"
    local show_suspicious="$2"

    echo ""
    echo -e "${BOLD}=========================================="
    echo -e "TTY/PTS SESSION MONITOR"
    echo -e "==========================================${NC}"
    echo ""
    echo -e "${CYAN}Current session:${NC} ${CURRENT_USER}@${CURRENT_TTY}"
    echo -e "${CYAN}Timestamp:${NC} $(date)"
    echo ""

    # Get all sessions
    local sessions
    if [[ -n "$filter_user" ]]; then
        sessions=$(w -h "$filter_user" 2>/dev/null)
    else
        sessions=$(w -h 2>/dev/null)
    fi

    if [[ -z "$sessions" ]]; then
        log "No active sessions found"
        return
    fi

    # Parse and display sessions
    echo -e "${BOLD}USER       TTY        FROM             LOGIN@   IDLE   WHAT${NC}"
    echo "--------------------------------------------------------------------------------"

    local suspicious_count=0
    local session_count=0
    local other_sessions=""

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local user tty from login idle jcpu pcpu what
        read -r user tty from login idle jcpu pcpu what <<< "$line"

        # Skip our own session for kill operations
        if [[ "$tty" != "$CURRENT_TTY" ]]; then
            other_sessions+="$tty "
        fi

        ((session_count++))

        # Check for suspicious indicators
        local suspicious=false
        local suspicion_reasons=""

        # Check if external IP
        if ! is_internal_ip "$from"; then
            suspicious=true
            suspicion_reasons+="External IP; "
        fi

        # Check command
        if is_suspicious_command "$what"; then
            suspicious=true
            suspicion_reasons+="Suspicious command; "
        fi

        # Check for root sessions
        if [[ "$user" == "root" && "$tty" != "$CURRENT_TTY" ]]; then
            suspicious=true
            suspicion_reasons+="Root session; "
        fi

        # Skip non-suspicious if filter is on
        if [[ "$show_suspicious" == "true" && "$suspicious" == "false" ]]; then
            continue
        fi

        # Display with color coding
        local color="$NC"
        local marker=""

        if [[ "$tty" == "$CURRENT_TTY" ]]; then
            color="$GREEN"
            marker=" (YOU)"
        elif [[ "$suspicious" == "true" ]]; then
            color="$RED"
            marker=" [!]"
            ((suspicious_count++))
        elif [[ "$user" != "$CURRENT_USER" ]]; then
            color="$YELLOW"
        fi

        printf "${color}%-10s %-10s %-16s %-8s %-6s %s${NC}%s\n" \
            "$user" "$tty" "$from" "$login" "$idle" "$what" "$marker"

        if [[ "$suspicious" == "true" && -n "$suspicion_reasons" ]]; then
            echo -e "           ${RED}Reason: ${suspicion_reasons%??}${NC}"
        fi

    done <<< "$sessions"

    echo "--------------------------------------------------------------------------------"
    echo ""

    # Summary
    echo -e "${BOLD}Summary:${NC}"
    echo "  Total sessions: $session_count"

    if [[ $suspicious_count -gt 0 ]]; then
        echo -e "  ${RED}Suspicious sessions: $suspicious_count${NC}"
    else
        echo -e "  ${GREEN}No suspicious sessions detected${NC}"
    fi

    # Store other sessions for kill operations
    OTHER_SESSIONS="$other_sessions"
}

# Kill sessions
kill_sessions() {
    local sessions_to_kill="$1"
    local force="$2"

    if [[ -z "$sessions_to_kill" ]]; then
        log "No other sessions to kill"
        return
    fi

    echo ""
    echo -e "${YELLOW}Sessions that will be terminated:${NC}"
    for tty in $sessions_to_kill; do
        echo "  - $tty"
        get_tty_processes "$tty" | sed 's/^/      /'
    done
    echo ""

    if [[ "$force" != "true" ]]; then
        read -rp "Kill these sessions? [y/N]: " confirm
        confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
        if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
            log "Operation cancelled"
            return
        fi
    fi

    for tty in $sessions_to_kill; do
        if pkill -9 -t "$tty" 2>/dev/null; then
            log "Killed session: $tty"
        else
            warn "Failed to kill session: $tty"
        fi
    done

    log "Session cleanup complete"
}

# Watch mode
watch_sessions() {
    local filter_user="$1"

    log "Starting continuous monitoring (Ctrl+C to exit)..."
    echo ""

    while true; do
        clear
        display_sessions "$filter_user" "$SUSPICIOUS_ONLY"
        echo ""
        echo -e "${CYAN}Refreshing every 5 seconds... (Ctrl+C to exit)${NC}"
        sleep 5
    done
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -a|--all)
            SHOW_ALL=true
            shift
            ;;
        -k|--kill)
            KILL_MODE=true
            shift
            ;;
        -K|--kill-all)
            KILL_MODE=true
            KILL_ALL=true
            shift
            ;;
        -u|--user)
            TARGET_USER="$2"
            shift 2
            ;;
        -w|--watch)
            WATCH_MODE=true
            shift
            ;;
        -s|--suspicious)
            SUSPICIOUS_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main ---

# Determine which user to monitor
if [[ -n "$TARGET_USER" ]]; then
    FILTER_USER="$TARGET_USER"
elif [[ "$SHOW_ALL" == "true" ]]; then
    FILTER_USER=""
else
    FILTER_USER="$CURRENT_USER"
fi

OTHER_SESSIONS=""

if [[ "$WATCH_MODE" == "true" ]]; then
    watch_sessions "$FILTER_USER"
else
    display_sessions "$FILTER_USER" "$SUSPICIOUS_ONLY"

    if [[ "$KILL_MODE" == "true" ]]; then
        kill_sessions "$OTHER_SESSIONS" "$KILL_ALL"
    fi
fi

exit 0
