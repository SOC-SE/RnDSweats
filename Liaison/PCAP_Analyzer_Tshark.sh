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

log_info()  { printf '%b[INFO]%b %s\n'  "${GREEN}" "${RESET}" "$1"; }
log_warn()  { printf '%b[WARN]%b %s\n'  "${YELLOW}" "${RESET}" "$1"; }
log_error() { printf '%b[ERROR]%b %s\n' "${RED}" "${RESET}" "$1" >&2; exit 1; }

# --- Globals ----------------------------------------------------------------
LOG_DIR="${TSHARK_LOG_DIR:-/var/log/tshark_logs}"
METADATA_FILE="${LOG_DIR}/.latest_capture"
LISTED_FILES=()
LAST_FILE=""
LAST_PCAP=""
LAST_STAMP=""
COLUMN_AVAILABLE=0
LESS_AVAILABLE=0
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
	if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
		log_warn "Unable to create $LOG_DIR (permission denied). Continuing anyway."
	fi
	[ -r "$LOG_DIR" ] || log_error "Cannot read from $LOG_DIR. Run as root or adjust permissions."
	if [ ! -w "$LOG_DIR" ]; then
		log_warn "Cannot write to $LOG_DIR. Saving filtered output may fail."
	fi
}

load_last_run_metadata() {
	[ -f "$METADATA_FILE" ] || return
	while IFS='=' read -r key value; do
		case "$key" in
			stamp) LAST_STAMP="$value" ;;
			log)   LAST_FILE="$value" ;;
			pcap)  LAST_PCAP="$value" ;;
		esac
	done < "$METADATA_FILE"
}

get_timestamp() {
	local target=$1
	local ts=""
	ts=$(stat -c %Y "$target" 2>/dev/null || true)
	if [ -z "$ts" ]; then
		ts=$(stat -f %m "$target" 2>/dev/null || true)
	fi
	printf '%s' "${ts:-0}"
}

collect_files() {
	LISTED_FILES=()
	local -a entries=()
	local path stamp tag label

	shopt -s nullglob
	for path in "$LOG_DIR"/*.pcap "$LOG_DIR"/*.log; do
		[ -e "$path" ] || continue
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

	IFS=$'\n' read -r -a entries <<< "$(printf '%s\n' "${entries[@]}" | sort -r)"

	log_info "Available artifacts (newest first):"
	local idx=1
	local entry
	for entry in "${entries[@]}"; do
		path=${entry#*::}
		path=${path%%::*}
		label=${entry##*::}
		printf '%2d) %s\n' "$idx" "$label"
		LISTED_FILES+=("$path")
		idx=$((idx+1))
	done
}

select_file() {
	collect_files
	local total=${#LISTED_FILES[@]}
	local default_index="" choice

	if [ -n "$LAST_FILE" ]; then
		local i
		for i in "${!LISTED_FILES[@]}"; do
			if [ "${LISTED_FILES[$i]}" = "$LAST_FILE" ]; then
				default_index=$((i+1))
				break
			fi
		done
	fi

	if [ -z "$default_index" ] && [ -n "$LAST_PCAP" ]; then
		local i
		for i in "${!LISTED_FILES[@]}"; do
			if [ "${LISTED_FILES[$i]}" = "$LAST_PCAP" ]; then
				default_index=$((i+1))
				break
			fi
		done
	fi

	while true; do
		local prompt="Select file number"
		[ -n "$default_index" ] && prompt+=" [$default_index]"
		prompt+=" (1-$total): "
		read -r -p "$prompt" choice || exit 1
		if [ -z "$choice" ] && [ -n "$default_index" ]; then
			choice=$default_index
		fi
		if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$total" ]; then
			printf '%s' "${LISTED_FILES[$((choice-1))]}"
			return 0
		fi
		log_warn "Invalid selection."
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

	local file="$LOG_DIR/${prefix}_$(date +"%Y-%m-%d_%H-%M-%S").txt"
	{
		printf '%s\n' "$headers"
		printf '%s\n' "$LINE_BAR"
		printf '%s\n' "$body"
	} > "$file"
	log_info "Saved output to $file"
}

run_pcap_filter() {
	local pcap=$1
	local filter=$2
	local fields=${3:-}
	local headers=$4
	local output=""
	local -a args=()

	log_info "Applying filter '$filter' to $(basename "$pcap")"

	if [ -n "$fields" ]; then
		# shellcheck disable=SC2206
		args=($fields)
		output=$(tshark -r "$pcap" -Y "$filter" -T fields "${args[@]}" 2>/dev/null || true)
	else
		output=$(tshark -r "$pcap" -Y "$filter" 2>/dev/null || true)
	fi

	if [ -z "$output" ]; then
		log_warn "No results for filter '$filter'."
		return 1
	fi

	display_table "$headers" "$output"
	ask_to_save "filtered_${filter//[^A-Za-z0-9]/_}" "$headers" "$output"
	return 0
}

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

	if [ -z "$output" ]; then
		output=$(awk -v pat="$pattern" -v use_regex="$use_regex" 'BEGIN{IGNORECASE=1}
			{
				if (use_regex==1) {
					if ($0 ~ pat) print $0;
				} else {
					if (index($0, pat) > 0) print $0;
				}
			}' "$log_file" 2>/dev/null || true)
	fi

	if [ -z "$output" ]; then
		log_warn "No results for pattern '$pattern'."
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
		log_warn "less not available; showing tail of file."
		tail -n 200 "$file"
	fi
}

summarize_file() {
	local file=$1
	log_info "Summary for $(basename "$file"):"
	if [[ "$file" == *.pcap ]]; then
		tshark -r "$file" -q -z io,stat,0,"COUNT" || log_warn "Stat summary failed (tshark permissions?)."
	else
		local lines words bytes
		if read -r lines words bytes _ < <(wc -l -w -c "$file" 2>/dev/null); then
			printf 'Lines: %s  Words: %s  Bytes: %s\n' "$lines" "$words" "$bytes"
		fi
		printf '\nTop talkers (count of unique IPs)\n'
		awk '{for(i=1;i<=NF;i++){if($i~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)print $i}}' "$file" | sort | uniq -c | sort -nr | head -n 10 || true
	fi
}

filter_http_pcap() {
	run_pcap_filter "$1" "http" "-e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code" \
		"Time\tSource\tDestination\tMethod\tURI\tResponse"
}

filter_http_log() {
	run_log_filter "$1" "HTTP" "Lines Containing HTTP"
}

filter_dns_pcap() {
	run_pcap_filter "$1" "dns" "-e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type" \
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
	run_pcap_filter "$pcap" "tcp.port == $port || udp.port == $port" \
		"-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto" \
		"Time\tSource\tDestination\tSrc Port\tDst Port\tProto"
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
	run_pcap_filter "$pcap" "ip.addr == $ip" \
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
	run_log_filter "$1" 'tcp\\.flags\\.syn|SYN' "Lines Containing SYN" 1
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

filter_creds_log() {
	run_log_filter "$1" 'password|pass=|login|credential' "Lines Containing Credential Keywords" 1
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

filter_tcp_stats_log() {
	local log_file=$1
	local output
	output=$(awk 'BEGIN{capture=0}
		/TCP Conversations/ {capture=1}
		capture && /^-+$/ {print; exit}
		capture {print}' "$log_file" 2>/dev/null || true)
	if [ -z "$output" ]; then
		log_warn "Unable to locate TCP conversation section in log."
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

prompt_filter() {
	local file=$1
	local is_pcap=0
	[[ "$file" == *.pcap ]] && is_pcap=1

	log_info "Operating on $(basename "$file")"
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
		1) if [ $is_pcap -eq 1 ]; then filter_http_pcap "$file"; else filter_http_log "$file"; fi ;;
		2) if [ $is_pcap -eq 1 ]; then filter_dns_pcap "$file"; else filter_dns_log "$file"; fi ;;
		3) if [ $is_pcap -eq 1 ]; then filter_port_pcap "$file"; else filter_port_log "$file"; fi ;;
		4) if [ $is_pcap -eq 1 ]; then filter_ip_pcap "$file"; else filter_ip_log "$file"; fi ;;
		5) if [ $is_pcap -eq 1 ]; then filter_tcp_syn_pcap "$file"; else filter_tcp_syn_log "$file"; fi ;;
		6) if [ $is_pcap -eq 1 ]; then filter_creds_pcap "$file"; else filter_creds_log "$file"; fi ;;
		7) if [ $is_pcap -eq 1 ]; then filter_tcp_stats_pcap "$file"; else filter_tcp_stats_log "$file"; fi ;;
		8) filter_custom "$file" ;;
		9) view_raw_file "$file" ;;
		10) summarize_file "$file" ;;
		11) return 1 ;;
		12) exit 0 ;;
		*) log_warn "Invalid choice." ;;
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
		file=$(select_file)
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
