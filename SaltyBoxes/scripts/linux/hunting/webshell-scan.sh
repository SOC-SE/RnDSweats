#!/usr/bin/env bash
#
# PHP Webshell Scanner
#
# Scans web-accessible directories for PHP files containing patterns commonly
# found in webshells. Designed for rapid triage — not a replacement for YARA
# or ClamAV, but fast enough to run repeatedly during an incident.
#
# USAGE:
#   ./webshellScan.sh [directory]    # default: /var/www
#   ./webshellScan.sh --watch        # monitor web roots with inotifywait
#
# EXIT CODES:
#   0 — no suspicious files found
#   1 — suspicious files found
#   2 — error

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Configuration ───────────────────────────────────────────────────────────
SCAN_DIR="${1:-/var/www}"
LOG_FILE="/var/log/webshell_scan.log"
QUARANTINE_DIR="/var/quarantine/webshells"

# Patterns that strongly indicate a webshell. Each is a grep -P regex.
# Grouped by severity: critical (almost always malicious) and suspicious (needs review).
CRITICAL_PATTERNS=(
    'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    'eval\s*\(\s*base64_decode\s*\('
    'eval\s*\(\s*gzinflate\s*\('
    'eval\s*\(\s*gzuncompress\s*\('
    'eval\s*\(\s*str_rot13\s*\('
    'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    'preg_replace\s*\(\s*["\x27]/[^/]*/e\s*,'
    '\bsystem\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    '\bpassthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    '\bshell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    '\bexec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    '\bpopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    '\bproc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    'base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    '\bc99shell\b|\br57shell\b|\bWSO\s'
    'FilesMan|b374k|p0wny'
)

SUSPICIOUS_PATTERNS=(
    '\beval\s*\(\s*\$[a-zA-Z_]'
    '\bcreate_function\s*\('
    '\bcall_user_func\s*\(\s*\$'
    '\barray_map\s*\(\s*\$[^,]*,\s*\$_(GET|POST|REQUEST)'
    '\busort\s*\(\s*\$[^,]*,\s*\$_(GET|POST|REQUEST)'
    '\b\$\{["\x27]\$_(GET|POST|REQUEST)'
    'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr'
    '\bfile_put_contents\s*\(.*\$_(GET|POST|REQUEST)'
    '\bmove_uploaded_file\s*\('
    '\bstr_replace\s*\(.*\beval\b'
    '\bini_set\s*\(\s*["\x27]disable_functions'
    '\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}'
)

# ── Functions ───────────────────────────────────────────────────────────────

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

print_finding() {
    local severity="$1" file="$2" pattern="$3" line="$4"
    if [[ "$severity" == "CRITICAL" ]]; then
        echo -e "${RED}[CRITICAL]${NC} ${file}"
    else
        echo -e "${YELLOW}[SUSPICIOUS]${NC} ${file}"
    fi
    echo -e "  Pattern: ${CYAN}${pattern}${NC}"
    # Show truncated matching line
    local truncated
    truncated="$(echo "$line" | head -c 200)"
    echo -e "  Match:   ${truncated}"
    echo ""
    log "${severity}: ${file} — pattern: ${pattern}"
}

scan_directory() {
    local dir="$1"
    local found=0

    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Error: Directory '$dir' does not exist.${NC}" >&2
        exit 2
    fi

    echo -e "${CYAN}Scanning ${dir} for PHP webshells...${NC}"
    echo ""

    # Find all PHP files (including disguised extensions)
    local php_files
    php_files=$(find "$dir" -type f \( -name "*.php" -o -name "*.php5" -o -name "*.php7" \
        -o -name "*.phtml" -o -name "*.pht" -o -name "*.phps" -o -name "*.phar" \
        -o -name "*.inc" \) 2>/dev/null) || true

    if [[ -z "$php_files" ]]; then
        echo -e "${GREEN}No PHP files found in ${dir}.${NC}"
        return 0
    fi

    local file_count
    file_count=$(echo "$php_files" | wc -l)
    echo -e "Found ${file_count} PHP files to scan."
    echo ""

    # Check for recently modified files (last 24h) — a quick anomaly signal
    echo -e "${CYAN}── Recently modified PHP files (last 24h) ──${NC}"
    local recent
    recent=$(find "$dir" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.pht" \
        -o -name "*.phar" \) -mtime -1 2>/dev/null) || true
    if [[ -n "$recent" ]]; then
        echo -e "${YELLOW}${recent}${NC}"
        echo ""
    else
        echo -e "${GREEN}None.${NC}"
        echo ""
    fi

    # Check for PHP files in upload directories
    echo -e "${CYAN}── PHP files in upload/image directories ──${NC}"
    local upload_php
    upload_php=$(find "$dir" -type f -name "*.php" \( -path "*/upload*" -o -path "*/uploads*" \
        -o -path "*/image*" -o -path "*/images*" -o -path "*/tmp*" -o -path "*/cache*" \
        -o -path "*/media*" \) 2>/dev/null) || true
    if [[ -n "$upload_php" ]]; then
        echo -e "${RED}${upload_php}${NC}"
        found=1
        echo ""
    else
        echo -e "${GREEN}None.${NC}"
        echo ""
    fi

    # Scan for critical patterns
    echo -e "${CYAN}── Pattern scan ──${NC}"
    echo ""

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue

        for pattern in "${CRITICAL_PATTERNS[@]}"; do
            local match
            match=$(grep -Pn "$pattern" "$file" 2>/dev/null | head -1) || true
            if [[ -n "$match" ]]; then
                print_finding "CRITICAL" "$file" "$pattern" "$match"
                found=1
                break  # one hit per file is enough for critical
            fi
        done

        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            local match
            match=$(grep -Pn "$pattern" "$file" 2>/dev/null | head -1) || true
            if [[ -n "$match" ]]; then
                print_finding "SUSPICIOUS" "$file" "$pattern" "$match"
                found=1
                break
            fi
        done
    done <<< "$php_files"

    return $found
}

quarantine_file() {
    local file="$1"
    mkdir -p "$QUARANTINE_DIR"
    local basename
    basename="$(basename "$file").$(date +%s)"
    chmod 000 "$file"
    mv "$file" "${QUARANTINE_DIR}/${basename}"
    log "QUARANTINED: ${file} -> ${QUARANTINE_DIR}/${basename}"
    echo -e "${RED}Quarantined:${NC} ${file} -> ${QUARANTINE_DIR}/${basename}"
}

interactive_review() {
    local dir="$1"

    echo ""
    echo -e "${CYAN}── Interactive quarantine mode ──${NC}"
    echo "Review each finding and choose to quarantine or skip."
    echo ""

    local php_files
    php_files=$(find "$dir" -type f \( -name "*.php" -o -name "*.php5" -o -name "*.php7" \
        -o -name "*.phtml" -o -name "*.pht" -o -name "*.phps" -o -name "*.phar" \
        -o -name "*.inc" \) 2>/dev/null) || true

    [[ -z "$php_files" ]] && return 0

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue

        for pattern in "${CRITICAL_PATTERNS[@]}"; do
            local match
            match=$(grep -Pn "$pattern" "$file" 2>/dev/null | head -1) || true
            if [[ -n "$match" ]]; then
                print_finding "CRITICAL" "$file" "$pattern" "$match"
                read -r -p "Quarantine this file? [y/N] " answer </dev/tty
                if [[ "$answer" =~ ^[Yy] ]]; then
                    quarantine_file "$file"
                fi
                break
            fi
        done
    done <<< "$php_files"
}

watch_mode() {
    if ! command -v inotifywait >/dev/null 2>&1; then
        echo -e "${RED}inotifywait not found. Install inotify-tools:${NC}"
        echo "  apt-get install -y inotify-tools   # Debian/Ubuntu"
        echo "  dnf install -y inotify-tools        # RHEL/Fedora"
        exit 2
    fi

    local watch_dir="${SCAN_DIR}"
    echo -e "${CYAN}Watching ${watch_dir} for new/modified PHP files...${NC}"
    echo "Press Ctrl+C to stop."
    log "WATCH started on ${watch_dir}"

    inotifywait -m -r -e create -e modify -e moved_to \
        --include '\.(php|phtml|pht|phar|php5|php7)$' \
        "$watch_dir" 2>/dev/null | while IFS= read -r event; do

        local file
        file=$(echo "$event" | awk '{print $1 $3}')
        [[ -f "$file" ]] || continue

        echo -e "${YELLOW}[$(date '+%H:%M:%S')] File event: ${file}${NC}"

        for pattern in "${CRITICAL_PATTERNS[@]}"; do
            local match
            match=$(grep -Pn "$pattern" "$file" 2>/dev/null | head -1) || true
            if [[ -n "$match" ]]; then
                print_finding "CRITICAL" "$file" "$pattern" "$match"
                break
            fi
        done
    done
}

usage() {
    echo "Usage: $0 [OPTIONS] [directory]"
    echo ""
    echo "Options:"
    echo "  --watch         Monitor web roots for new/modified PHP files"
    echo "  --quarantine    Interactive mode: review and quarantine findings"
    echo "  --help          Show this help"
    echo ""
    echo "Default scan directory: /var/www"
}

# ── Main ────────────────────────────────────────────────────────────────────

case "${1:-}" in
    --watch)
        watch_mode
        ;;
    --quarantine)
        shift
        SCAN_DIR="${1:-/var/www}"
        scan_directory "$SCAN_DIR" || true
        interactive_review "$SCAN_DIR"
        ;;
    --help|-h)
        usage
        ;;
    *)
        found=0
        scan_directory "$SCAN_DIR" || found=$?
        if [[ $found -eq 0 ]]; then
            echo -e "${GREEN}No webshells detected.${NC}"
        else
            echo -e "${RED}Suspicious files found! Review the output above.${NC}"
            echo -e "Run with ${CYAN}--quarantine${NC} to interactively remove them."
        fi
        exit $found
        ;;
esac
