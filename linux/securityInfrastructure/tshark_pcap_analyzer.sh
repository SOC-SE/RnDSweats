#!/bin/bash

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

set -euo pipefail

# --- Styling ---------------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

# All logging goes to stderr so pick_file can be called inside $() safely.
# The only stdout output from pick_file is the final selected file path.
log_info()  { printf '%b[INFO]%b %s\n'  "${GREEN}"  "${RESET}" "$1" >&2; }
log_warn()  { printf '%b[WARN]%b %s\n'  "${YELLOW}" "${RESET}" "$1" >&2; }
log_error() { printf '%b[ERROR]%b %s\n' "${RED}"    "${RESET}" "$1" >&2; exit 1; }

# --- Globals ----------------------------------------------------------------
# Must match the LOG_DIR used by Network_Scanner_Tshark.sh.
# Override by setting TSHARK_LOG_DIR in the environment before running.
LOG_DIR="${TSHARK_LOG_DIR:-/var/log/tshark_logs}"
METADATA_FILE="${LOG_DIR}/.latest_capture"
LISTED_FILES=()
LAST_FILE=""
LAST_PCAP=""
LAST_STAMP=""
COLUMN_AVAILABLE=0
LESS_AVAILABLE=0
LOG_DIR_OK=1      # set to 0 by ensure_log_dir if dir is missing/unreadable
LINE_BAR='------------------------------------------------------------------'

# --- Utility ----------------------------------------------------------------
print_banner() {
    cat <<'BANNER'
====================================================================
 PCAP Analyzer with Tshark  |  Companion to Network_Scanner_Tshark
====================================================================
BANNER
}

require_cmd() {
    local name=$1
    command -v "$name" >/dev/null 2>&1 || log_error "Required dependency '$name' is missing."
}

check_dependencies() {
    require_cmd tshark
    command -v column >/dev/null 2>&1 && COLUMN_AVAILABLE=1
    command -v less   >/dev/null 2>&1 && LESS_AVAILABLE=1
}

ensure_log_dir() {
    # The scanner runs as root and owns LOG_DIR. The analyzer may run as a
    # normal user, so we warn rather than hard-fail — the user can still work
    # by entering a file path manually (option M in pick_file).
    if [ ! -d "$LOG_DIR" ]; then
        log_warn "$LOG_DIR does not exist. Use the manual path option to load a file directly."
        LOG_DIR_OK=0
        return
    fi
    if [ ! -r "$LOG_DIR" ]; then
        log_warn "Cannot read $LOG_DIR. Try: sudo chmod o+rx $LOG_DIR, or use the manual path option."
        LOG_DIR_OK=0
        return
    fi
    if [ ! -w "$LOG_DIR" ]; then
        log_warn "Cannot write to $LOG_DIR. Saving filtered output will be disabled."
    fi
    LOG_DIR_OK=1
}

# ---------------------------------------------------------------------------
# load_last_run_metadata
# Reads the .latest_capture file written by Network_Scanner_Tshark.sh.
# Format (written by the scanner):
#   stamp=HH-MM-SS_XXXX
#   log=/var/log/tshark_logs/<label>_HH-MM-SS_XXXX.log
#   pcap=/var/log/tshark_logs/capture_HH-MM-SS_XXXX.pcap
# ---------------------------------------------------------------------------
load_last_run_metadata() {
    [ -f "$METADATA_FILE" ] || return
    while IFS='=' read -r key value; do
        case "$key" in
            stamp) LAST_STAMP="$value" ;;
            log)   LAST_FILE="$value"  ;;
            pcap)  LAST_PCAP="$value"  ;;
        esac
    done < "$METADATA_FILE"
}

get_timestamp() {
    local target=$1
    local ts=""
    # GNU stat (Linux)
    ts=$(stat -c %Y "$target" 2>/dev/null || true)
    # BSD stat (macOS)
    if [ -z "$ts" ]; then
        ts=$(stat -f %m "$target" 2>/dev/null || true)
    fi
    printf '%s' "${ts:-0}"
}

# ---------------------------------------------------------------------------
# collect_files
# Scans LOG_DIR for *.pcap and *.log files, sorts them newest-first, and
# populates LISTED_FILES[]. Tags the entries that match the last scanner run
# so the user can quickly identify them.
#
# Compatible with the scanner's time-only stamp format (HH-MM-SS_XXXX) as
# well as any older YYYY-MM-DD style files that may still be present.
# ---------------------------------------------------------------------------
collect_files() {
    LISTED_FILES=()
    local -a entries=()
    local path stamp tag label

    shopt -s nullglob
    for path in "$LOG_DIR"/*.pcap "$LOG_DIR"/*.log; do
        [ -e "$path" ] || continue

        # Skip the hidden metadata file itself
        [ "$(basename "$path")" = ".latest_capture" ] && continue

        stamp=$(get_timestamp "$path")

        tag=""
        if [ -n "$LAST_FILE" ] && [ "$path" = "$LAST_FILE" ]; then
            tag=" [last-log]"
        elif [ -n "$LAST_PCAP" ] && [ "$path" = "$LAST_PCAP" ]; then
            tag=" [last-pcap]"
        fi

        label="$(basename "$path")${tag}"
        entries+=("$stamp::$path::$label")
    done
    shopt -u nullglob

    if [ ${#entries[@]} -eq 0 ]; then
        log_error "No PCAP or log files found under $LOG_DIR. Run Network_Scanner_Tshark.sh first."
    fi

    # Sort by mtime descending so the most recent capture appears first
    IFS=$'\n' read -r -a entries <<< "$(printf '%s\n' "${entries[@]}" | sort -r)"

    log_info "Available artifacts (newest first):"
    local idx=1
    local entry
    for entry in "${entries[@]}"; do
        path="${entry#*::}"
        path="${path%%::*}"
        label="${entry##*::}"
        printf '  %2d) %s\n' "$idx" "$label" >&2
        LISTED_FILES+=("$path")
        idx=$((idx+1))
    done
}

# ---------------------------------------------------------------------------
# pick_file
# Entry point for file selection. Offers three routes:
#   A) Auto-scan LOG_DIR and pick from a numbered list  (requires read access)
#   M) Type an absolute or relative file path manually  (always available)
#   L) Jump straight to the last file from the scanner  (when metadata exists)
# This replaces the old select_file() which hard-failed when LOG_DIR was
# empty, missing, or unreadable (common when the analyzer runs without root).
# ---------------------------------------------------------------------------
pick_file() {
    local file=""

    while true; do
        echo "" >&2
        echo "How would you like to select a file?" >&2
        echo "" >&2
        echo "  [A] Auto-scan log directory  — list all captures in $LOG_DIR" >&2
        echo "  [M] Manual path              — type the full path to any .pcap or .log file" >&2
        if [ -n "$LAST_PCAP" ] || [ -n "$LAST_FILE" ]; then
            local last_label="${LAST_PCAP:-$LAST_FILE}"
            echo "  [L] Last scanner file        — jump straight to: $(basename "$last_label")" >&2
        fi
        echo "  [Q] Quit" >&2
        echo "" >&2

        local mode
        read -r -p "Choice [A/M/L/Q]: " mode || exit 1
        mode="${mode^^}"   # uppercase

        case "$mode" in

            A)  # ── Auto-scan ────────────────────────────────────────────
                if [ "$LOG_DIR_OK" -eq 0 ]; then
                    log_warn "Cannot scan $LOG_DIR (missing or unreadable). Use M to enter a path."
                    continue
                fi
                collect_files
                local total=${#LISTED_FILES[@]}
                local default_index="" choice

                if [ -n "$LAST_FILE" ]; then
                    local i
                    for i in "${!LISTED_FILES[@]}"; do
                        if [ "${LISTED_FILES[$i]}" = "$LAST_FILE" ]; then
                            default_index=$((i+1)); break
                        fi
                    done
                fi
                if [ -z "$default_index" ] && [ -n "$LAST_PCAP" ]; then
                    local i
                    for i in "${!LISTED_FILES[@]}"; do
                        if [ "${LISTED_FILES[$i]}" = "$LAST_PCAP" ]; then
                            default_index=$((i+1)); break
                        fi
                    done
                fi

                while true; do
                    local prompt="Select file number"
                    [ -n "$default_index" ] && prompt+=" [$default_index]"
                    prompt+=" (1-$total): "
                    read -r -p "$prompt" choice || exit 1
                    [ -z "$choice" ] && [ -n "$default_index" ] && choice=$default_index
                    if [[ "$choice" =~ ^[0-9]+$ ]] &&                        [ "$choice" -ge 1 ] && [ "$choice" -le "$total" ]; then
                        file="${LISTED_FILES[$((choice-1))]}"
                        break
                    fi
                    log_warn "Enter a number between 1 and $total."
                done
                ;;

            M)  # ── Manual path ──────────────────────────────────────────
                while true; do
                    read -r -p "File path (.pcap or .log): " file || exit 1
                    file="${file/#\~/$HOME}"   # expand leading ~
                    if [ -z "$file" ]; then
                        log_warn "Path cannot be empty."
                    elif [ ! -f "$file" ]; then
                        log_warn "File not found: $file"
                    elif [[ "$file" != *.pcap && "$file" != *.log ]]; then
                        log_warn "File must be a .pcap or .log file."
                    else
                        break
                    fi
                done
                ;;

            L)  # ── Last scanner file ─────────────────────────────────────
                if [ -z "$LAST_PCAP" ] && [ -z "$LAST_FILE" ]; then
                    log_warn "No last-run metadata found. Run the scanner first."
                    continue
                fi
                # Prefer PCAP if available, fall back to log
                file="${LAST_PCAP:-$LAST_FILE}"
                if [ ! -f "$file" ]; then
                    log_warn "Last file no longer exists: $file"
                    log_warn "Use A or M to select a different file."
                    continue
                fi
                log_info "Using last scanner file: $(basename "$file")"
                ;;

            Q)  exit 0 ;;

            *)  log_warn "Enter A, M, L, or Q." ; continue ;;
        esac

        # Got a valid file — return it
        printf '%s' "$file"
        return 0
    done
}

update_last_selection() {
    local file=$1
    if [[ "$file" == *.pcap ]]; then
        LAST_PCAP="$file"
    else
        LAST_FILE="$file"
    fi
}

display_table() {
    local headers=$1
    local body=$2
    printf '%b%s%b\n' "${BOLD}" "$headers" "${RESET}"
    printf '%s\n' "$LINE_BAR"
    if [ $COLUMN_AVAILABLE -eq 1 ]; then
        printf '%s\n' "$body" | column -t -s $'\t'
    else
        printf '%s\n' "$body"
    fi
    printf '%s\n' "$LINE_BAR"
}

# ---------------------------------------------------------------------------
# ask_to_save
# Uses a time-only stamp (HH-MM-SS_XXXX) to match the naming convention of
# the scanner's own output files, keeping LOG_DIR consistent.
# ---------------------------------------------------------------------------
ask_to_save() {
    local prefix=$1
    local headers=$2
    local body=$3
    local answer

    read -r -p "Save this output to $LOG_DIR? (y/N): " answer || return
    if [[ ! $answer =~ ^[Yy]$ ]]; then
        return
    fi

    if [ ! -w "$LOG_DIR" ]; then
        log_warn "Cannot write to $LOG_DIR; skipping save."
        return
    fi

    # Time-only stamp matches the scanner's generate_stamp() convention
    local stamp
    stamp=$(printf '%s_%04d' "$(date +"%H-%M-%S")" "$((RANDOM % 10000))")
    local file="$LOG_DIR/${prefix}_${stamp}.txt"
    {
        printf '%s\n' "$headers"
        printf '%s\n' "$LINE_BAR"
        printf '%s\n' "$body"
    } > "$file"
    log_info "Saved output to $file"
}

# ---------------------------------------------------------------------------
# run_pcap_filter
# Applies a tshark display filter to a PCAP file and extracts specific fields.
#
# Key design decisions:
#  - stderr is captured separately and shown to the user on failure so errors
#    like "permission denied" or "invalid filter" are never silently swallowed.
#  - Fields are passed as an eval-safe array built with read, not word-split
#    from a string, so filters containing spaces work correctly.
#  - A readable file check runs before tshark so we give a clear message
#    instead of a cryptic tshark error.
# ---------------------------------------------------------------------------
run_pcap_filter() {
    local pcap=$1
    local filter=$2
    local fields=${3:-}
    local headers=$4
    local output="" errmsg="" tmpout tmperr

    log_info "Applying filter '$filter' to $(basename "$pcap")"

    # Verify file is readable before handing it to tshark
    if [ ! -r "$pcap" ]; then
        log_warn "Cannot read: $pcap"
        log_warn "If you are not root, re-run with: sudo bash $(basename "$0")"
        return 1
    fi

    tmpout=$(mktemp)
    tmperr=$(mktemp)

    if [ -n "$fields" ]; then
        # Build the -e argument array safely from the space-separated field string
        local -a field_args=()
        read -r -a field_args <<< "$fields"
        tshark -r "$pcap" -Y "$filter" -T fields "${field_args[@]}"             > "$tmpout" 2> "$tmperr" || true
    else
        tshark -r "$pcap" -Y "$filter"             > "$tmpout" 2> "$tmperr" || true
    fi

    output=$(cat "$tmpout")
    errmsg=$(cat "$tmperr")
    rm -f "$tmpout" "$tmperr"

    # Surface any tshark errors/warnings to the user
    if [ -n "$errmsg" ]; then
        log_warn "tshark stderr: $errmsg"
    fi

    if [ -z "$output" ]; then
        log_warn "No results for filter '$filter'."
        log_warn "Tip: use option 9 (View raw file) to confirm the PCAP has traffic."
        return 1
    fi

    display_table "$headers" "$output"
    ask_to_save "filtered_${filter//[^A-Za-z0-9]/_}" "$headers" "$output"
    return 0
}

# ---------------------------------------------------------------------------
# run_log_filter
# Searches a scanner-generated .log file for a pattern.
# Scanner log format (from run_tshark in Network_Scanner_Tshark.sh):
#   Tshark Output - HH-MM-SS_XXXX
#   Command: tshark ...
#   ----------------------------------------
#   <tshark output>
# The header lines are included in grep results but don't cause issues —
# they simply appear as context in the output table.
# ---------------------------------------------------------------------------
run_log_filter() {
    local log_file=$1
    local pattern=$2
    local headers=$3
    local use_regex=${4:-0}
    local output=""

    log_info "Searching $(basename "$log_file") with pattern '$pattern'"

    if [ "$use_regex" -eq 1 ]; then
        output=$(grep -Ei "$pattern" "$log_file" 2>/dev/null || true)
    else
        output=$(grep -iF -- "$pattern" "$log_file" 2>/dev/null || true)
    fi

    # Fallback to awk if grep returned nothing (e.g. on minimal Alpine installs)
    if [ -z "$output" ]; then
        output=$(awk -v pat="$pattern" -v use_regex="$use_regex" \
            'BEGIN{IGNORECASE=1}
             {
                 if (use_regex==1) { if ($0 ~ pat) print $0 }
                 else              { if (index($0, pat) > 0) print $0 }
             }' "$log_file" 2>/dev/null || true)
    fi

    if [ -z "$output" ]; then
        log_warn "No results for pattern '$pattern' in $(basename "$log_file")."
        log_warn "Tip: use option 9 (View raw file) to inspect the log contents directly."
        return 1
    fi

    display_table "$headers" "$output"
    ask_to_save "log_filter" "$headers" "$output"
    return 0
}

view_raw_file() {
    local file=$1
    if [ $LESS_AVAILABLE -eq 1 ]; then
        log_info "Opening $(basename "$file") in less (press q to quit)."
        less -R "$file"
    else
        log_warn "less not available; showing last 200 lines."
        tail -n 200 "$file"
    fi
}

# ---------------------------------------------------------------------------
# summarize_file
# For PCAPs: uses tshark's io,stat to show packet counts over time.
# For .log files: shows line/word/byte counts and top IPs mentioned.
# The log header written by the scanner (stamp, command line) is included
# in the word/byte count but does not affect the IP extraction.
# ---------------------------------------------------------------------------
summarize_file() {
    local file=$1
    log_info "Summary for $(basename "$file"):"
    if [[ "$file" == *.pcap ]]; then
        tshark -r "$file" -q -z io,stat,0 2>/dev/null \
            || log_warn "Stat summary failed — check tshark permissions."
    else
        local lines words bytes
        if read -r lines words bytes _ < <(wc -l -w -c "$file" 2>/dev/null); then
            printf 'Lines: %s  Words: %s  Bytes: %s\n' "$lines" "$words" "$bytes"
        fi
        printf '\nTop talkers (unique IPs, up to 10)\n'
        awk '{
            for (i=1; i<=NF; i++) {
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i
            }
        }' "$file" | sort | uniq -c | sort -nr | head -n 10 || true
    fi
}

# ============================================================
# Per-type filter functions
# Each has a _pcap and _log variant, dispatched by prompt_filter.
# ============================================================

filter_http_pcap() {
    run_pcap_filter "$1" "http" \
        "-e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code" \
        "Time\tSource\tDestination\tMethod\tURI\tResponse"
}

filter_http_log() {
    run_log_filter "$1" "HTTP" "Lines Containing HTTP"
}

filter_dns_pcap() {
    run_pcap_filter "$1" "dns" \
        "-e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type" \
        "Time\tSource\tDestination\tQuery\tType"
}

filter_dns_log() {
    run_log_filter "$1" "DNS" "Lines Containing DNS"
}

filter_port_pcap() {
    local pcap=$1
    local port
    read -r -p "Port number: " port || return
    while [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; do
        log_warn "Enter a numeric port."
        read -r -p "Port number: " port || return
    done
    # Parentheses are required — without them tshark may mis-parse the OR
    # on some versions and silently return no results even when packets match.
    run_pcap_filter "$pcap" "(tcp.port == $port) || (udp.port == $port)" \
        "-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.proto" \
        "Time\tSource\tDestination\tTCP Src\tTCP Dst\tUDP Src\tUDP Dst\tProto"
}

filter_port_log() {
    local log_file=$1
    local port
    read -r -p "Port number: " port || return
    while [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; do
        log_warn "Enter a numeric port."
        read -r -p "Port number: " port || return
    done
    run_log_filter "$log_file" "$port" "Lines Containing Port $port"
}

filter_ip_pcap() {
    local pcap=$1
    local ip
    read -r -p "IP address: " ip || return
    while [ -z "$ip" ]; do
        log_warn "IP cannot be empty."
        read -r -p "IP address: " ip || return
    done
    run_pcap_filter "$pcap" "(ip.addr == $ip)" \
        "-e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len" \
        "Time\tSource\tDestination\tProto\tLength"
}

filter_ip_log() {
    local log_file=$1
    local ip
    read -r -p "IP address: " ip || return
    while [ -z "$ip" ]; do
        log_warn "IP cannot be empty."
        read -r -p "IP address: " ip || return
    done
    run_log_filter "$log_file" "$ip" "Lines Containing $ip"
}

filter_tcp_syn_pcap() {
    run_pcap_filter "$1" "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
        "-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags" \
        "Time\tSource\tDestination\tSrc Port\tDst Port\tFlags"
}

filter_tcp_syn_log() {
    run_log_filter "$1" 'tcp\.flags\.syn|SYN' "Lines Containing SYN" 1
}

filter_creds_pcap() {
    local pcap=$1
    local output
    output=$(tshark -r "$pcap" -q -z credentials 2>&1 || true)
    output=$(printf '%s\n' "$output" | sed '/^\s*$/d')
    if [ -z "$output" ]; then
        log_warn "No credential artifacts reported by tshark."
        return 1
    fi
    display_table "Extracted Credentials" "$output"
    ask_to_save "credentials" "Extracted Credentials" "$output"
    return 0
}

# ---------------------------------------------------------------------------
# filter_creds_log
# Searches for credential-related keywords in a scanner log.
# The scanner's credential extraction (option 8) uses tshark -z credentials
# which produces output like:
#   Credentials
#   Protocol  Username  Password  ...
# This regex catches both the tshark -z output headers and any raw keyword
# matches if the log contains plaintext credential data.
# ---------------------------------------------------------------------------
filter_creds_log() {
    run_log_filter "$1" 'password|pass=|user=|username|login|credential' \
        "Lines Containing Credential Keywords" 1
}

filter_tcp_stats_pcap() {
    local pcap=$1
    local output
    output=$(tshark -r "$pcap" -q -z conv,tcp 2>/dev/null || true)
    output=$(printf '%s\n' "$output" | sed '/^\s*$/d')
    if [ -z "$output" ]; then
        log_warn "No TCP conversation data available."
        return 1
    fi
    display_table "TCP Conversation Statistics" "$output"
    ask_to_save "tcp_stats" "TCP Conversation Statistics" "$output"
    return 0
}

# ---------------------------------------------------------------------------
# filter_tcp_stats_log
# Extracts the TCP conversation table from a scanner log produced by
# option 7 (TCP Conversation Statistics). The scanner writes the tshark
# -z conv,tcp output directly into the log after the header block:
#   Tshark Output - HH-MM-SS_XXXX
#   Command: tshark -i eth0 -c 500 -z conv,tcp -q
#   ----------------------------------------
#   <tshark conv,tcp output here>
# We skip the 3-line header then grab everything after.
# ---------------------------------------------------------------------------
filter_tcp_stats_log() {
    local log_file=$1
    local output

    # Try to find the tshark -z conv,tcp table (starts with "TCP Conversations")
    output=$(awk '
        /TCP Conversations/ { capture=1 }
        capture { print }
    ' "$log_file" 2>/dev/null || true)

    # Fallback: if the log has the scanner header block, skip it and show the rest
    if [ -z "$output" ]; then
        output=$(awk '
            /^-{3,}$/ && found_cmd { body=1; next }
            /^Command:/ { found_cmd=1 }
            body { print }
        ' "$log_file" 2>/dev/null || true)
    fi

    output=$(printf '%s\n' "$output" | sed '/^\s*$/d')

    if [ -z "$output" ]; then
        log_warn "Unable to locate TCP conversation data in log. Was the log generated by option 7?"
        return 1
    fi

    display_table "TCP Conversation Statistics" "$output"
    ask_to_save "tcp_stats_log" "TCP Conversation Statistics" "$output"
    return 0
}

filter_custom() {
    local file=$1
    local filter
    read -r -p "Custom filter/pattern: " filter || return
    while [ -z "$filter" ]; do
        log_warn "Filter cannot be blank."
        read -r -p "Custom filter/pattern: " filter || return
    done

    if [[ "$file" == *.pcap ]]; then
        local fields headers
        read -r -p "Field list (-e args, blank for defaults): " fields || return
        fields=${fields:-"-e frame.time -e ip.src -e ip.dst -e ip.proto"}
        read -r -p "Header labels (tab separated): " headers || return
        headers=${headers:-"Time\tSource\tDestination\tProtocol"}
        run_pcap_filter "$file" "$filter" "$fields" "$headers"
    else
        local headers
        read -r -p "Header label: " headers || return
        headers=${headers:-"Filtered Lines"}
        run_log_filter "$file" "$filter" "$headers"
    fi
}

# ---------------------------------------------------------------------------
# prompt_filter
# Shows the per-file action menu and dispatches to the correct _pcap or _log
# variant based on the selected file's extension.
# Returns 1 when the user selects "Back to file list" so the caller can break.
# ---------------------------------------------------------------------------
prompt_filter() {
    local file=$1
    local is_pcap=0
    [[ "$file" == *.pcap ]] && is_pcap=1

    echo ""
    log_info "Operating on: $(basename "$file")"
    cat <<'MENU'
 1) Filter HTTP traffic
 2) Filter DNS queries
 3) Filter by port number
 4) Filter by IP address
 5) TCP SYN scan check
 6) Extract credentials
 7) TCP conversation stats
 8) Custom filter
 9) View raw file
10) File summary
11) Back to file list
12) Exit
MENU
    local choice
    read -r -p "Select option (1-12): " choice || exit 1
    case "$choice" in
        1)  if [ $is_pcap -eq 1 ]; then filter_http_pcap      "$file"; else filter_http_log      "$file"; fi ;;
        2)  if [ $is_pcap -eq 1 ]; then filter_dns_pcap       "$file"; else filter_dns_log       "$file"; fi ;;
        3)  if [ $is_pcap -eq 1 ]; then filter_port_pcap      "$file"; else filter_port_log      "$file"; fi ;;
        4)  if [ $is_pcap -eq 1 ]; then filter_ip_pcap        "$file"; else filter_ip_log        "$file"; fi ;;
        5)  if [ $is_pcap -eq 1 ]; then filter_tcp_syn_pcap   "$file"; else filter_tcp_syn_log   "$file"; fi ;;
        6)  if [ $is_pcap -eq 1 ]; then filter_creds_pcap     "$file"; else filter_creds_log     "$file"; fi ;;
        7)  if [ $is_pcap -eq 1 ]; then filter_tcp_stats_pcap "$file"; else filter_tcp_stats_log "$file"; fi ;;
        8)  filter_custom   "$file" ;;
        9)  view_raw_file   "$file" ;;
        10) summarize_file  "$file" ;;
        11) return 1 ;;
        12) exit 0 ;;
        *)  log_warn "Invalid choice '$choice'. Select 1-12." ;;
    esac
    return 0
}

main() {
    print_banner
    check_dependencies
    ensure_log_dir
    load_last_run_metadata

    while true; do
        local file
        file=$(pick_file)
        update_last_selection "$file"

        while true; do
            prompt_filter "$file" || break
            local again
            read -r -p "Run another operation on this file? (y/N): " again || exit 1
            [[ $again =~ ^[Yy]$ ]] || break
        done

        local another
        read -r -p "Analyze another file? (y/N): " another || exit 1
        [[ $another =~ ^[Yy]$ ]] || break
    done

    log_info "Analyzer complete. Generated artifacts (if any) are in $LOG_DIR."
}

main "$@"
