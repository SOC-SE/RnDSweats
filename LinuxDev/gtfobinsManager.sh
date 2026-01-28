#!/bin/bash
# ==============================================================================
# Script Name: gtfobinsManager.sh
# Description: Manage GTFOBins - binaries that can be exploited for privilege
#              escalation, shell escape, or file operations. Disable or restore.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./gtfobinsManager.sh [options] <action>
#
# Actions:
#   list       List GTFOBins present on system
#   disable    Move GTFOBins to quarantine and remove execute permission
#   restore    Restore GTFOBins from quarantine
#   check      Check which GTFOBins are present (audit mode)
#
# Options:
#   -h, --help       Show this help message
#   -a, --all        Apply to all GTFOBins
#   -b, --binary     Specific binary to manage
#   -d, --dir        Quarantine directory (default: /opt/gtfobins-disabled)
#   -n, --dry-run    Show what would be done without making changes
#   -s, --safe       Only disable high-risk binaries
#   -y, --yes        Skip confirmation prompts
#
# Risk Categories:
#   HIGH   - Direct shell escape or code execution (nc, ncat, python, perl)
#   MEDIUM - File operations or limited shell access (vim, find, awk)
#   LOW    - Require specific conditions to exploit (less, man)
#
# Supported Systems:
#   - All Linux distributions
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - No GTFOBins found
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
QUARANTINE_DIR="/opt/gtfobins-disabled"
DRY_RUN=false
SAFE_MODE=false
YES_MODE=false
SPECIFIC_BINARY=""
ALL_MODE=false

# GTFOBins with risk levels
# Format: "binary:risk_level:category"
declare -A GTFOBINS_HIGH=(
    ["nc"]="Network - reverse shell"
    ["ncat"]="Network - reverse shell"
    ["netcat"]="Network - reverse shell"
    ["socat"]="Network - reverse shell"
    ["python"]="Interpreter - code execution"
    ["python2"]="Interpreter - code execution"
    ["python3"]="Interpreter - code execution"
    ["perl"]="Interpreter - code execution"
    ["ruby"]="Interpreter - code execution"
    ["lua"]="Interpreter - code execution"
    ["php"]="Interpreter - code execution"
    ["node"]="Interpreter - code execution"
    ["gdb"]="Debugger - code execution"
    ["strace"]="Debugger - code execution"
    ["ltrace"]="Debugger - code execution"
    ["expect"]="Automation - shell spawn"
    ["rlwrap"]="Wrapper - TTY spawn"
    ["script"]="Terminal - TTY spawn"
    ["telnet"]="Network - reverse shell"
    ["ftp"]="Network - command execution"
)

declare -A GTFOBINS_MEDIUM=(
    ["vim"]="Editor - shell escape"
    ["vi"]="Editor - shell escape"
    ["nano"]="Editor - shell escape"
    ["ed"]="Editor - shell escape"
    ["emacs"]="Editor - shell escape"
    ["find"]="File - command execution"
    ["awk"]="Text - command execution"
    ["gawk"]="Text - command execution"
    ["sed"]="Text - limited execution"
    ["tar"]="Archive - file write/read"
    ["zip"]="Archive - file write"
    ["unzip"]="Archive - file write"
    ["rsync"]="Sync - file operations"
    ["scp"]="Network - file transfer"
    ["sftp"]="Network - file transfer"
    ["wget"]="Network - file download"
    ["curl"]="Network - file download"
    ["dd"]="Disk - file operations"
    ["cp"]="File - copy anywhere"
    ["mv"]="File - move anywhere"
    ["chmod"]="Permission - change perms"
    ["chown"]="Permission - change owner"
    ["env"]="Environment - command execution"
    ["xargs"]="Execution - command chaining"
)

declare -A GTFOBINS_LOW=(
    ["less"]="Pager - shell escape (needs !)"
    ["more"]="Pager - limited shell"
    ["man"]="Pager - shell escape"
    ["watch"]="Monitor - command execution"
    ["tee"]="Output - file write"
    ["time"]="Timing - command execution"
    ["timeout"]="Timing - command execution"
    ["nice"]="Priority - command execution"
    ["ionice"]="Priority - command execution"
    ["taskset"]="CPU - command execution"
    ["busybox"]="Multi-tool - various"
    ["ash"]="Shell - alternative shell"
    ["dash"]="Shell - alternative shell"
    ["csh"]="Shell - alternative shell"
    ["tcsh"]="Shell - alternative shell"
    ["ksh"]="Shell - alternative shell"
    ["zsh"]="Shell - alternative shell"
)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# --- Helper Functions ---
usage() {
    head -50 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Get binary path
get_binary_path() {
    local binary="$1"
    command -v "$binary" 2>/dev/null
}

# Get all binary paths (some may be in multiple locations)
get_all_binary_paths() {
    local binary="$1"
    local paths=()

    # Check common locations
    for dir in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin; do
        if [[ -x "$dir/$binary" ]]; then
            paths+=("$dir/$binary")
        fi
    done

    # Also check PATH
    local which_path
    which_path=$(command -v "$binary" 2>/dev/null)
    if [[ -n "$which_path" && ! " ${paths[*]} " =~ " $which_path " ]]; then
        paths+=("$which_path")
    fi

    echo "${paths[@]}"
}

# List all GTFOBins on system
list_gtfobins() {
    echo "========================================"
    echo "GTFOBins Present on System"
    echo "========================================"
    echo ""

    local found_count=0

    echo -e "${RED}${BOLD}HIGH RISK (Shell/Code Execution):${NC}"
    for binary in "${!GTFOBINS_HIGH[@]}"; do
        local path
        path=$(get_binary_path "$binary")
        if [[ -n "$path" ]]; then
            printf "  ${RED}%-15s${NC} %-30s %s\n" "$binary" "${GTFOBINS_HIGH[$binary]}" "$path"
            ((found_count++))
        fi
    done
    echo ""

    echo -e "${YELLOW}${BOLD}MEDIUM RISK (File Operations/Limited Shell):${NC}"
    for binary in "${!GTFOBINS_MEDIUM[@]}"; do
        local path
        path=$(get_binary_path "$binary")
        if [[ -n "$path" ]]; then
            printf "  ${YELLOW}%-15s${NC} %-30s %s\n" "$binary" "${GTFOBINS_MEDIUM[$binary]}" "$path"
            ((found_count++))
        fi
    done
    echo ""

    echo -e "${CYAN}${BOLD}LOW RISK (Requires Specific Conditions):${NC}"
    for binary in "${!GTFOBINS_LOW[@]}"; do
        local path
        path=$(get_binary_path "$binary")
        if [[ -n "$path" ]]; then
            printf "  ${CYAN}%-15s${NC} %-30s %s\n" "$binary" "${GTFOBINS_LOW[$binary]}" "$path"
            ((found_count++))
        fi
    done
    echo ""

    echo "========================================"
    echo "Total GTFOBins found: $found_count"
    echo "========================================"

    # Check quarantine
    if [[ -d "$QUARANTINE_DIR" ]]; then
        local quarantined
        quarantined=$(ls -1 "$QUARANTINE_DIR" 2>/dev/null | wc -l)
        if [[ $quarantined -gt 0 ]]; then
            echo ""
            echo "Quarantined binaries in $QUARANTINE_DIR: $quarantined"
            ls -1 "$QUARANTINE_DIR" 2>/dev/null | while read -r bin; do
                echo "  - $bin"
            done
        fi
    fi
}

# Disable a specific binary
disable_binary() {
    local binary="$1"
    local paths
    paths=$(get_all_binary_paths "$binary")

    if [[ -z "$paths" ]]; then
        warn "Binary not found: $binary"
        return 1
    fi

    for path in $paths; do
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "[DRY-RUN] Would move $path to $QUARANTINE_DIR/"
            echo "[DRY-RUN] Would chmod -x $QUARANTINE_DIR/$binary"
        else
            # Create quarantine directory
            mkdir -p "$QUARANTINE_DIR"

            # Store original location
            echo "$path" > "$QUARANTINE_DIR/.${binary}.origin"

            # Move binary
            mv "$path" "$QUARANTINE_DIR/" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                # Remove execute permission
                chmod -x "$QUARANTINE_DIR/$binary" 2>/dev/null
                log "Disabled: $binary (from $path)"
            else
                error "Failed to move: $path"
                return 1
            fi
        fi
    done

    return 0
}

# Restore a specific binary
restore_binary() {
    local binary="$1"

    if [[ ! -f "$QUARANTINE_DIR/$binary" ]]; then
        warn "Binary not in quarantine: $binary"
        return 1
    fi

    # Get original location
    local origin_file="$QUARANTINE_DIR/.${binary}.origin"
    local original_path="/usr/bin/$binary"

    if [[ -f "$origin_file" ]]; then
        original_path=$(cat "$origin_file")
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would move $QUARANTINE_DIR/$binary to $original_path"
        echo "[DRY-RUN] Would chmod +x $original_path"
    else
        # Restore execute permission first
        chmod +x "$QUARANTINE_DIR/$binary"

        # Move back
        mv "$QUARANTINE_DIR/$binary" "$original_path" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            rm -f "$origin_file"
            log "Restored: $binary to $original_path"
        else
            error "Failed to restore: $binary"
            return 1
        fi
    fi

    return 0
}

# Disable all or selected GTFOBins
disable_gtfobins() {
    local binaries_to_disable=()

    if [[ -n "$SPECIFIC_BINARY" ]]; then
        binaries_to_disable+=("$SPECIFIC_BINARY")
    elif [[ "$SAFE_MODE" == "true" ]]; then
        # Only HIGH risk binaries
        for binary in "${!GTFOBINS_HIGH[@]}"; do
            if [[ -n "$(get_binary_path "$binary")" ]]; then
                binaries_to_disable+=("$binary")
            fi
        done
    else
        # All GTFOBins
        for binary in "${!GTFOBINS_HIGH[@]}"; do
            if [[ -n "$(get_binary_path "$binary")" ]]; then
                binaries_to_disable+=("$binary")
            fi
        done
        for binary in "${!GTFOBINS_MEDIUM[@]}"; do
            if [[ -n "$(get_binary_path "$binary")" ]]; then
                binaries_to_disable+=("$binary")
            fi
        done
    fi

    if [[ ${#binaries_to_disable[@]} -eq 0 ]]; then
        log "No GTFOBins to disable"
        return 0
    fi

    echo "Binaries to disable:"
    for bin in "${binaries_to_disable[@]}"; do
        echo "  - $bin"
    done
    echo ""

    if [[ "$YES_MODE" == "false" && "$DRY_RUN" == "false" ]]; then
        read -rp "Proceed with disabling these binaries? [y/N]: " confirm
        confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
        if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
            log "Operation cancelled"
            return 0
        fi
    fi

    local success=0
    local failed=0

    for binary in "${binaries_to_disable[@]}"; do
        if disable_binary "$binary"; then
            ((success++))
        else
            ((failed++))
        fi
    done

    echo ""
    log "Disabled: $success, Failed: $failed"
}

# Restore all quarantined binaries
restore_gtfobins() {
    if [[ ! -d "$QUARANTINE_DIR" ]]; then
        log "Quarantine directory does not exist"
        return 0
    fi

    local binaries_to_restore=()

    if [[ -n "$SPECIFIC_BINARY" ]]; then
        binaries_to_restore+=("$SPECIFIC_BINARY")
    else
        while IFS= read -r -d '' file; do
            local basename
            basename=$(basename "$file")
            if [[ ! "$basename" =~ ^\. ]]; then
                binaries_to_restore+=("$basename")
            fi
        done < <(find "$QUARANTINE_DIR" -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    if [[ ${#binaries_to_restore[@]} -eq 0 ]]; then
        log "No binaries to restore"
        return 0
    fi

    echo "Binaries to restore:"
    for bin in "${binaries_to_restore[@]}"; do
        echo "  - $bin"
    done
    echo ""

    if [[ "$YES_MODE" == "false" && "$DRY_RUN" == "false" ]]; then
        read -rp "Proceed with restoring these binaries? [y/N]: " confirm
        confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
        if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
            log "Operation cancelled"
            return 0
        fi
    fi

    local success=0
    local failed=0

    for binary in "${binaries_to_restore[@]}"; do
        if restore_binary "$binary"; then
            ((success++))
        else
            ((failed++))
        fi
    done

    echo ""
    log "Restored: $success, Failed: $failed"
}

# --- Parse Arguments ---
ACTION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -a|--all)
            ALL_MODE=true
            shift
            ;;
        -b|--binary)
            SPECIFIC_BINARY="$2"
            shift 2
            ;;
        -d|--dir)
            QUARANTINE_DIR="$2"
            shift 2
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -s|--safe)
            SAFE_MODE=true
            shift
            ;;
        -y|--yes)
            YES_MODE=true
            shift
            ;;
        list|disable|restore|check)
            ACTION="$1"
            shift
            ;;
        *)
            error "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -z "$ACTION" ]]; then
    error "No action specified"
    usage
fi

# --- Main ---
echo "========================================"
echo "GTFOBins Manager"
echo "Time: $(date)"
echo "========================================"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    warn "DRY-RUN MODE - No changes will be made"
    echo ""
fi

case "$ACTION" in
    list|check)
        list_gtfobins
        ;;
    disable)
        check_root
        disable_gtfobins
        ;;
    restore)
        check_root
        restore_gtfobins
        ;;
esac

exit 0
