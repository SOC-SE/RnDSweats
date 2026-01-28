#!/bin/bash
# ==============================================================================
# Script Name: virusTotalScan.sh
# Description: Scan files against VirusTotal API for malware detection
#              Supports single file, directory, and batch scanning
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./virusTotalScan.sh [options] <file|directory>
#
# Options:
#   -h, --help       Show this help message
#   -k, --key KEY    VirusTotal API key (or set VT_API_KEY env var)
#   -u, --upload     Upload unknown files to VirusTotal for analysis
#   -r, --recursive  Scan directories recursively
#   -q, --quiet      Only show malicious results
#   -o, --output     Output results to file (JSON format)
#   -t, --threshold  Detection threshold (default: 1)
#
# API Key:
#   Get a free API key at: https://www.virustotal.com/gui/join-us
#   Set via: export VT_API_KEY="your-api-key"
#   Or use: ./virusTotalScan.sh -k "your-api-key" <file>
#
# Rate Limits:
#   Free API: 4 requests/minute, 500 requests/day
#   Script includes automatic rate limiting
#
# Exit Codes:
#   0 - All files clean
#   1 - Malicious files detected
#   2 - Error (missing API key, network error, etc.)
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
API_KEY="${VT_API_KEY:-}"
VT_API_URL="https://www.virustotal.com/api/v3"
UPLOAD_UNKNOWN=false
RECURSIVE=false
QUIET=false
OUTPUT_FILE=""
THRESHOLD=1
RATE_LIMIT_DELAY=15  # Seconds between requests (free API = 4/min)

# Counters
TOTAL_SCANNED=0
MALICIOUS_COUNT=0
CLEAN_COUNT=0
UNKNOWN_COUNT=0
ERROR_COUNT=0

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -45 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

malicious() {
    echo -e "${RED}[MALICIOUS]${NC} $1"
}

clean() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[CLEAN]${NC} $1"
}

unknown() {
    [[ "$QUIET" == "false" ]] && echo -e "${YELLOW}[UNKNOWN]${NC} $1"
}

# Calculate SHA256 hash of a file
get_sha256() {
    local file="$1"
    sha256sum "$file" 2>/dev/null | cut -d' ' -f1
}

# Query VirusTotal for a file hash
vt_lookup() {
    local hash="$1"
    local response

    response=$(curl -s --max-time 30 \
        -H "x-apikey: $API_KEY" \
        "$VT_API_URL/files/$hash" 2>/dev/null)

    echo "$response"
}

# Upload a file to VirusTotal
vt_upload() {
    local file="$1"
    local response

    response=$(curl -s --max-time 120 \
        -H "x-apikey: $API_KEY" \
        -F "file=@$file" \
        "$VT_API_URL/files" 2>/dev/null)

    echo "$response"
}

# Parse VirusTotal response
parse_response() {
    local response="$1"
    local file="$2"
    local hash="$3"

    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_code
        error_code=$(echo "$response" | grep -oP '"code"\s*:\s*"\K[^"]+' | head -1)

        if [[ "$error_code" == "NotFoundError" ]]; then
            echo "UNKNOWN"
            return
        else
            echo "ERROR:$error_code"
            return
        fi
    fi

    # Extract malicious count
    local malicious_count
    malicious_count=$(echo "$response" | grep -oP '"malicious"\s*:\s*\K[0-9]+' | head -1)

    if [[ -z "$malicious_count" ]]; then
        echo "PARSE_ERROR"
        return
    fi

    # Extract other stats
    local suspicious_count harmless_count undetected_count
    suspicious_count=$(echo "$response" | grep -oP '"suspicious"\s*:\s*\K[0-9]+' | head -1 || echo "0")
    harmless_count=$(echo "$response" | grep -oP '"harmless"\s*:\s*\K[0-9]+' | head -1 || echo "0")
    undetected_count=$(echo "$response" | grep -oP '"undetected"\s*:\s*\K[0-9]+' | head -1 || echo "0")

    echo "RESULT:$malicious_count:$suspicious_count:$harmless_count:$undetected_count"
}

# Scan a single file
scan_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        warn "Not a file: $file"
        return
    fi

    if [[ ! -r "$file" ]]; then
        warn "Cannot read: $file"
        ((ERROR_COUNT++))
        return
    fi

    # Skip very large files (>32MB for free API)
    local size
    size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    if [[ "$size" -gt 33554432 ]]; then
        warn "File too large (>32MB): $file"
        ((ERROR_COUNT++))
        return
    fi

    ((TOTAL_SCANNED++))

    local hash
    hash=$(get_sha256 "$file")

    [[ "$QUIET" == "false" ]] && echo -ne "${CYAN}[SCAN]${NC} $file ... "

    # Rate limiting
    if [[ $TOTAL_SCANNED -gt 1 ]]; then
        sleep "$RATE_LIMIT_DELAY"
    fi

    local response
    response=$(vt_lookup "$hash")

    local result
    result=$(parse_response "$response" "$file" "$hash")

    case "$result" in
        UNKNOWN)
            if [[ "$UPLOAD_UNKNOWN" == "true" ]]; then
                [[ "$QUIET" == "false" ]] && echo "uploading..."
                local upload_response
                upload_response=$(vt_upload "$file")

                if echo "$upload_response" | grep -q '"id"'; then
                    local analysis_id
                    analysis_id=$(echo "$upload_response" | grep -oP '"id"\s*:\s*"\K[^"]+' | head -1)
                    unknown "$file (uploaded, analysis ID: $analysis_id)"
                    echo "  Track progress: https://www.virustotal.com/gui/file/$hash"
                else
                    error "Upload failed for $file"
                    ((ERROR_COUNT++))
                fi
            else
                [[ "$QUIET" == "false" ]] && echo ""
                unknown "$file (not in VT database)"
                echo "  SHA256: $hash"
                echo "  Use -u/--upload to submit for analysis"
            fi
            ((UNKNOWN_COUNT++))
            ;;

        ERROR:*)
            [[ "$QUIET" == "false" ]] && echo ""
            local err_msg="${result#ERROR:}"
            error "$file - API error: $err_msg"
            ((ERROR_COUNT++))
            ;;

        PARSE_ERROR)
            [[ "$QUIET" == "false" ]] && echo ""
            error "$file - Failed to parse response"
            ((ERROR_COUNT++))
            ;;

        RESULT:*)
            local stats="${result#RESULT:}"
            IFS=':' read -r mal_count sus_count harm_count undet_count <<< "$stats"

            if [[ "$mal_count" -ge "$THRESHOLD" ]]; then
                [[ "$QUIET" == "false" ]] && echo ""
                malicious "$file"
                echo -e "  ${RED}Detections: $mal_count malicious, $sus_count suspicious${NC}"
                echo "  SHA256: $hash"
                echo "  Link: https://www.virustotal.com/gui/file/$hash"
                ((MALICIOUS_COUNT++))

                # Log to output file if specified
                if [[ -n "$OUTPUT_FILE" ]]; then
                    echo "{\"file\":\"$file\",\"hash\":\"$hash\",\"malicious\":$mal_count,\"suspicious\":$sus_count,\"status\":\"malicious\"}" >> "$OUTPUT_FILE"
                fi
            else
                [[ "$QUIET" == "false" ]] && echo "clean ($mal_count detections)"
                ((CLEAN_COUNT++))

                if [[ -n "$OUTPUT_FILE" ]]; then
                    echo "{\"file\":\"$file\",\"hash\":\"$hash\",\"malicious\":$mal_count,\"suspicious\":$sus_count,\"status\":\"clean\"}" >> "$OUTPUT_FILE"
                fi
            fi
            ;;
    esac
}

# Scan a directory
scan_directory() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        error "Not a directory: $dir"
        return
    fi

    log "Scanning directory: $dir"

    if [[ "$RECURSIVE" == "true" ]]; then
        find "$dir" -type f 2>/dev/null | while read -r file; do
            scan_file "$file"
        done
    else
        for file in "$dir"/*; do
            [[ -f "$file" ]] && scan_file "$file"
        done
    fi
}

# --- Parse Arguments ---
TARGETS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -k|--key)
            API_KEY="$2"
            shift 2
            ;;
        -u|--upload)
            UPLOAD_UNKNOWN=true
            shift
            ;;
        -r|--recursive)
            RECURSIVE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -t|--threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            ;;
        *)
            TARGETS+=("$1")
            shift
            ;;
    esac
done

# --- Validation ---
if [[ -z "$API_KEY" ]]; then
    error "VirusTotal API key required"
    echo ""
    echo "Set via environment variable:"
    echo "  export VT_API_KEY=\"your-api-key\""
    echo ""
    echo "Or use command line option:"
    echo "  $0 -k \"your-api-key\" <file>"
    echo ""
    echo "Get a free API key at: https://www.virustotal.com/gui/join-us"
    exit 2
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    error "No target file or directory specified"
    usage
fi

# Check for curl
if ! command -v curl &>/dev/null; then
    error "curl is required but not installed"
    exit 2
fi

# --- Main ---
echo "========================================"
echo "VIRUSTOTAL FILE SCANNER"
echo "Time: $(date)"
echo "========================================"
echo ""

log "Detection threshold: $THRESHOLD"
log "Upload unknown files: $UPLOAD_UNKNOWN"
log "Rate limit delay: ${RATE_LIMIT_DELAY}s between requests"
echo ""

# Initialize output file
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "[" > "$OUTPUT_FILE"
fi

# Process targets
for target in "${TARGETS[@]}"; do
    if [[ -d "$target" ]]; then
        scan_directory "$target"
    elif [[ -f "$target" ]]; then
        scan_file "$target"
    else
        warn "Target not found: $target"
    fi
done

# Close output file
if [[ -n "$OUTPUT_FILE" ]]; then
    # Remove trailing comma and close array
    sed -i '$ s/,$//' "$OUTPUT_FILE" 2>/dev/null || true
    echo "]" >> "$OUTPUT_FILE"
    log "Results saved to: $OUTPUT_FILE"
fi

# --- Summary ---
echo ""
echo "========================================"
echo "SCAN SUMMARY"
echo "========================================"
echo ""
echo "Total files scanned: $TOTAL_SCANNED"
echo -e "Clean files:         ${GREEN}$CLEAN_COUNT${NC}"
echo -e "Malicious files:     ${RED}$MALICIOUS_COUNT${NC}"
echo -e "Unknown files:       ${YELLOW}$UNKNOWN_COUNT${NC}"
echo -e "Errors:              $ERROR_COUNT"
echo ""

if [[ $MALICIOUS_COUNT -gt 0 ]]; then
    echo -e "${RED}WARNING: Malicious files detected!${NC}"
    echo "Review the results above and quarantine/delete malicious files."
    exit 1
else
    echo -e "${GREEN}No malicious files detected.${NC}"
    exit 0
fi
