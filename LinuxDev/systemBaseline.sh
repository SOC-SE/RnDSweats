#!/bin/bash
# ==============================================================================
# Script Name: systemBaseline.sh
# Description: Captures system state to numbered snapshots and shows diff from
#              previous run to identify changes (useful for detecting compromise)
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./systemBaseline.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -d, --dir        Base directory for baselines (default: /var/baseline)
#   -c, --compare    Only compare last two snapshots, don't create new one
#   -n, --number     Compare specific snapshot number against current
#   -q, --quiet      Only show differences, not full output
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#   - Alpine Linux
#
# Exit Codes:
#   0 - Success
#   1 - Differences found
#   2 - Script error
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
BASELINE_DIR="/var/baseline"
COMPARE_ONLY=false
COMPARE_NUMBER=""
QUIET=false
HOSTNAME=$(hostname)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -30 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[CHANGED]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 2
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -d|--dir)
            BASELINE_DIR="$2"
            shift 2
            ;;
        -c|--compare)
            COMPARE_ONLY=true
            shift
            ;;
        -n|--number)
            COMPARE_NUMBER="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Functions ---
get_next_snapshot_number() {
    mkdir -p "$BASELINE_DIR"
    chmod 700 "$BASELINE_DIR"

    local latest
    latest=$(ls -1 "$BASELINE_DIR" 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tail -n 1)

    if [[ -z "$latest" ]]; then
        echo "1"
    else
        echo $((latest + 1))
    fi
}

get_latest_snapshot_number() {
    ls -1 "$BASELINE_DIR" 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tail -n 1
}

gather_system_info() {
    local output_dir="$1"

    echo "=== System Information ===" > "$output_dir/system_info.txt"
    echo "Hostname: $(hostname)" >> "$output_dir/system_info.txt"
    echo "Date: $(date)" >> "$output_dir/system_info.txt"
    uname -a >> "$output_dir/system_info.txt"

    # OS Release
    cat /etc/os-release >> "$output_dir/system_info.txt" 2>/dev/null
}

gather_network_info() {
    local output_dir="$1"

    {
        echo "=== Network Interfaces ==="
        ip a 2>/dev/null || ifconfig 2>/dev/null

        echo ""
        echo "=== Routes ==="
        ip route show all 2>/dev/null || netstat -rn 2>/dev/null

        echo ""
        echo "=== Listening Ports ==="
        ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

        echo ""
        echo "=== Established Connections ==="
        ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED

        echo ""
        echo "=== Firewall Rules ==="
        iptables-save 2>/dev/null
        echo "--- IPv6 ---"
        ip6tables-save 2>/dev/null

        echo ""
        echo "=== Active Sessions ==="
        w 2>/dev/null

        echo ""
        echo "=== DNS Configuration ==="
        cat /etc/resolv.conf 2>/dev/null

        echo ""
        echo "=== Hosts File ==="
        cat /etc/hosts 2>/dev/null

    } > "$output_dir/network_info.txt"
}

gather_user_info() {
    local output_dir="$1"

    {
        echo "=== /etc/passwd ==="
        cat /etc/passwd

        echo ""
        echo "=== /etc/shadow (hashes redacted) ==="
        awk -F: '{print $1":"substr($2,1,3)"***:"$3":"$4":"$5":"$6":"$7":"$8":"$9}' /etc/shadow 2>/dev/null

        echo ""
        echo "=== /etc/group ==="
        cat /etc/group

        echo ""
        echo "=== Sudoers ==="
        cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] && echo "--- $f ---" && cat "$f" | grep -v "^#" | grep -v "^$"
        done

        echo ""
        echo "=== Users with UID 0 ==="
        awk -F: '$3 == 0 {print $1}' /etc/passwd

        echo ""
        echo "=== Users with login shells ==="
        grep -vE '(/false|/nologin|/sync|/shutdown|/halt)$' /etc/passwd

        echo ""
        echo "=== SSH Authorized Keys ==="
        for user_home in /home/* /root; do
            [[ -d "$user_home" ]] || continue
            user=$(basename "$user_home")
            if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
                echo "--- $user ---"
                wc -l < "$user_home/.ssh/authorized_keys"
                # Store hash of keys for comparison without exposing them
                sha256sum "$user_home/.ssh/authorized_keys" 2>/dev/null
            fi
        done

    } > "$output_dir/user_info.txt"
}

gather_process_info() {
    local output_dir="$1"

    {
        echo "=== Running Processes ==="
        ps aux --sort=-%mem | head -50

        echo ""
        echo "=== Process Tree ==="
        pstree -p 2>/dev/null || ps auxf

        echo ""
        echo "=== Crontabs ==="
        echo "--- System crontab ---"
        cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$"

        for user in $(cut -f1 -d: /etc/passwd); do
            local user_crontab
            user_crontab=$(crontab -u "$user" -l 2>/dev/null)
            if [[ -n "$user_crontab" ]]; then
                echo "--- Crontab: $user ---"
                echo "$user_crontab"
            fi
        done

        echo ""
        echo "=== Systemd Services (enabled) ==="
        systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -v "^UNIT"

        echo ""
        echo "=== Systemd Services (running) ==="
        systemctl list-units --type=service --state=running 2>/dev/null | grep -v "^UNIT" | grep -v "^$"

    } > "$output_dir/process_info.txt"
}

gather_package_info() {
    local output_dir="$1"

    {
        echo "=== Installed Packages ==="

        if command -v dpkg &>/dev/null; then
            dpkg -l | grep "^ii" | awk '{print $2"\t"$3}'
        elif command -v rpm &>/dev/null; then
            rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\n' | sort
        elif command -v apk &>/dev/null; then
            apk list --installed 2>/dev/null
        else
            echo "Package manager not detected"
        fi

    } > "$output_dir/packages.txt"
}

gather_filesystem_info() {
    local output_dir="$1"

    {
        echo "=== Disk Usage ==="
        df -h

        echo ""
        echo "=== Mounts ==="
        mount | grep -v "^cgroup" | grep -v "^systemd" | grep -v "^tmpfs"

        echo ""
        echo "=== fstab ==="
        cat /etc/fstab | grep -v "^#" | grep -v "^$"

        echo ""
        echo "=== SUID/SGID Binaries ==="
        find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort

        echo ""
        echo "=== World-Writable Directories ==="
        find / -type d -perm -002 2>/dev/null | grep -vE "^/(proc|sys|dev|run)" | sort

        echo ""
        echo "=== /etc file checksums ==="
        find /etc -type f -name "*.conf" -exec sha256sum {} \; 2>/dev/null | sort

    } > "$output_dir/filesystem_info.txt"
}

gather_persistence_info() {
    local output_dir="$1"

    {
        echo "=== Init Scripts ==="
        ls -la /etc/init.d/ 2>/dev/null

        echo ""
        echo "=== RC Local ==="
        cat /etc/rc.local 2>/dev/null
        cat /etc/rc.d/rc.local 2>/dev/null

        echo ""
        echo "=== Systemd Custom Services ==="
        find /etc/systemd/system -name "*.service" -type f 2>/dev/null | while read -r svc; do
            echo "--- $svc ---"
            cat "$svc"
        done

        echo ""
        echo "=== Kernel Modules ==="
        lsmod | sort

        echo ""
        echo "=== ld.so.preload ==="
        cat /etc/ld.so.preload 2>/dev/null || echo "(empty or not present)"

        echo ""
        echo "=== Profile Scripts ==="
        ls -la /etc/profile.d/ 2>/dev/null
        sha256sum /etc/profile /etc/bash.bashrc /etc/bashrc 2>/dev/null

    } > "$output_dir/persistence_info.txt"
}

create_snapshot() {
    local snapshot_num="$1"
    local snapshot_dir="$BASELINE_DIR/$snapshot_num"

    mkdir -p "$snapshot_dir"
    chmod 700 "$snapshot_dir"

    log "Creating snapshot #$snapshot_num in $snapshot_dir"

    log "Gathering system info..."
    gather_system_info "$snapshot_dir"

    log "Gathering network info..."
    gather_network_info "$snapshot_dir"

    log "Gathering user info..."
    gather_user_info "$snapshot_dir"

    log "Gathering process info..."
    gather_process_info "$snapshot_dir"

    log "Gathering package info..."
    gather_package_info "$snapshot_dir"

    log "Gathering filesystem info..."
    gather_filesystem_info "$snapshot_dir"

    log "Gathering persistence info..."
    gather_persistence_info "$snapshot_dir"

    # Create manifest
    echo "Snapshot: $snapshot_num" > "$snapshot_dir/manifest.txt"
    echo "Hostname: $HOSTNAME" >> "$snapshot_dir/manifest.txt"
    echo "Date: $(date)" >> "$snapshot_dir/manifest.txt"
    echo "Files:" >> "$snapshot_dir/manifest.txt"
    ls -la "$snapshot_dir" >> "$snapshot_dir/manifest.txt"

    log "Snapshot #$snapshot_num complete"
}

compare_snapshots() {
    local old_num="$1"
    local new_num="$2"
    local old_dir="$BASELINE_DIR/$old_num"
    local new_dir="$BASELINE_DIR/$new_num"
    local has_diff=false

    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Comparing Snapshot #$old_num vs #$new_num${NC}"
    echo -e "${CYAN}========================================${NC}"

    for file in system_info.txt network_info.txt user_info.txt process_info.txt packages.txt filesystem_info.txt persistence_info.txt; do
        if [[ -f "$old_dir/$file" && -f "$new_dir/$file" ]]; then
            local diff_output
            diff_output=$(diff -u "$old_dir/$file" "$new_dir/$file" 2>/dev/null)

            if [[ -n "$diff_output" ]]; then
                has_diff=true
                echo ""
                echo -e "${YELLOW}=== Changes in $file ===${NC}"
                echo "$diff_output" | head -100
                local diff_lines
                diff_lines=$(echo "$diff_output" | wc -l)
                if [[ $diff_lines -gt 100 ]]; then
                    echo -e "${BLUE}... ($((diff_lines - 100)) more lines)${NC}"
                fi
            fi
        fi
    done

    if [[ "$has_diff" == "false" ]]; then
        echo ""
        echo -e "${GREEN}No differences found between snapshots.${NC}"
        return 0
    else
        echo ""
        echo -e "${YELLOW}Differences detected! Review changes above.${NC}"
        return 1
    fi
}

# --- Main Execution ---
check_root

echo "========================================"
echo "SYSTEM BASELINE - $HOSTNAME"
echo "Time: $(date)"
echo "Baseline directory: $BASELINE_DIR"
echo "========================================"

if [[ "$COMPARE_ONLY" == "true" ]]; then
    # Just compare last two snapshots
    latest=$(get_latest_snapshot_number)
    if [[ -z "$latest" || "$latest" -lt 2 ]]; then
        error "Need at least 2 snapshots to compare"
        exit 2
    fi
    previous=$((latest - 1))
    compare_snapshots "$previous" "$latest"
    exit $?
fi

if [[ -n "$COMPARE_NUMBER" ]]; then
    # Compare specific snapshot against latest
    latest=$(get_latest_snapshot_number)
    if [[ -z "$latest" ]]; then
        error "No snapshots exist yet"
        exit 2
    fi
    if [[ ! -d "$BASELINE_DIR/$COMPARE_NUMBER" ]]; then
        error "Snapshot #$COMPARE_NUMBER does not exist"
        exit 2
    fi
    compare_snapshots "$COMPARE_NUMBER" "$latest"
    exit $?
fi

# Create new snapshot
next_num=$(get_next_snapshot_number)
create_snapshot "$next_num"

# If we have a previous snapshot, show diff
if [[ "$next_num" -gt 1 ]]; then
    previous_num=$((next_num - 1))
    compare_snapshots "$previous_num" "$next_num"
    diff_result=$?
else
    echo ""
    log "First snapshot created. Run again later to compare changes."
    diff_result=0
fi

echo ""
echo "========================================"
echo "Baseline snapshots stored in: $BASELINE_DIR"
echo "Current snapshot: #$next_num"
echo "========================================"

exit $diff_result
