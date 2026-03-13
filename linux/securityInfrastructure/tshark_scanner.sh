#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
  _______    _                _    
 |__   __|  | |              | |   
    | |___  | |__   __ _ _ __| | __
    | / __| | '_ \ / _` | '__| |/ /
    | \__ \ | | | | (_| | |  |   < 
    |_|___/ |_| |_|\__,_|_|  |_|\_\
                                   
EOF
echo -e "\033[0m"
echo "Network Scanner with Tshark"
echo "-----------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
LOG_DIR="${TSHARK_LOG_DIR:-/var/log/tshark_logs}"
METADATA_FILE="$LOG_DIR/.latest_capture"
mkdir -p "$LOG_DIR"
if command -v chown >/dev/null 2>&1; then
    chown root:root "$LOG_DIR" 2>/dev/null || true
fi

LAST_LOG_FILE=""
LAST_RUN_STAMP=""
LAST_PCAP_FILE=""

generate_stamp() {
    # Time-only stamp (HH-MM-SS) keeps filenames short and within OS limits.
    printf '%s_%04d' "$(date +"%H-%M-%S")" "$((RANDOM % 10000))"
}

# --- Helper Functions ---
# All user-facing output goes to stderr so that functions called inside $()
# don't have their messages captured into variables (causing garbled commands).
log_info()  { echo -e "${GREEN}[INFO] $1${NC}" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN] $1${NC}" >&2; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

record_run_metadata() {
    [ -n "$LAST_RUN_STAMP" ] || return
    local stored_pcap=""
    if [ -f "$METADATA_FILE" ]; then
        while IFS='=' read -r key value; do
            [ "$key" = "pcap" ] && stored_pcap="$value"
        done < "$METADATA_FILE"
    fi
    local pcap_value="${LAST_PCAP_FILE:-}"
    [ -z "$pcap_value" ] && [ -n "$stored_pcap" ] && pcap_value="$stored_pcap"
    {
        echo "stamp=$LAST_RUN_STAMP"
        echo "log=${LAST_LOG_FILE:-}"
        echo "pcap=$pcap_value"
    } > "$METADATA_FILE"
    chmod 600 "$METADATA_FILE" 2>/dev/null || true
}

# --- Progress bar (silent mode) ---
progress_bar() {
    local pid=$1
    local delay=0.2
    local spinstr='|/-\'
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}[WARNING] Scan in progress... Output logged to file.${NC}"
    echo -e "${YELLOW}[WARNING] Press Ctrl+C to stop (for live captures).${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    local timeout=300
    local start
    start=$(date +%s)
    while kill -0 "$pid" 2>/dev/null; do
        local elapsed=$(( $(date +%s) - start ))
        if [ "$elapsed" -ge "$timeout" ]; then
            log_warn "Progress timeout (${timeout}s) - assuming complete."
            break
        fi
        local temp="${spinstr#?}"
        printf " %c  " "${spinstr:0:1}"
        spinstr="${temp}${spinstr%"$temp"}"
        sleep "$delay"
        printf "\b\b\b"
    done
    printf " \b"
    echo -e "\n${GREEN}============================================================${NC}"
    echo -e "${GREEN}[COMPLETE] Scan finished. Check log for details.${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root for packet capture."
    fi
}

# --- Check if Tshark Installed ---
# Only called for options 1-10. Option 11 bypasses this check intentionally.
check_tshark() {
    if ! command -v tshark &>/dev/null; then
        log_error "Tshark not found. Select option 11 to install it."
    fi
    log_info "Tshark detected: $(tshark --version | head -1)"
}

# --- Get Network Interface ---
# Kali ships many extcap virtual interfaces (sshdump, ciscodump, randpkt, etc.).
# Selecting one causes "file name too long" because tshark generates a Unix socket
# path for them that exceeds the kernel hard limit of 108 bytes (sun_path in sockaddr_un).
# This function shows ONLY real kernel interfaces and rejects extcap names.
get_interface() {
    local extcap_pattern='randpkt|sshdump|ciscodump|udpdump|wifidump|androiddump|etwdump|sdjournal|dpauxmon|ecat-simon|f5fileinfo'

    log_info "Available REAL interfaces (extcap virtual interfaces hidden):"
    echo "---" >&2
    tshark -D 2>/dev/null | grep -vE "($extcap_pattern)" >&2 || true
    echo "---" >&2
    log_warn "Do NOT use extcap/virtual interfaces (sshdump, randpkt, etc.) --"
    log_warn "they trigger 'file name too long' due to a kernel Unix socket path limit."

    local iface
    while true; do
        read -rp "Enter interface name (e.g., eth0): " iface <&2 || read -rp "Enter interface name (e.g., eth0): " iface
        if [ -z "$iface" ]; then
            log_warn "Interface cannot be empty."
        elif echo "$iface" | grep -qE "($extcap_pattern)"; then
            log_warn "'$iface' is an extcap virtual interface and cannot be used for live capture."
        elif tshark -D 2>/dev/null | grep -qw "$iface"; then
            break
        else
            log_warn "Interface '$iface' not found. Choose one from the list above."
        fi
    done
    echo "$iface"   # this is the ONLY stdout output — the return value
}

# --- Core runner ---
run_tshark() {
    local label="$1"
    shift
    local display="silent"
    local stamp=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --tee)   display="tee"; shift ;;
            --stamp) stamp="$2"; shift 2 ;;
            --)      shift; break ;;
            *)       break ;;
        esac
    done

    [ -z "$stamp" ] && stamp=$(generate_stamp)

    local log_file="$LOG_DIR/${label}_${stamp}.log"
    local -a cmd=("$@")

    if [ ${#cmd[@]} -eq 0 ]; then
        log_error "Internal error: run_tshark called without a command."
    fi

    log_info "Command : ${cmd[*]}"
    log_info "Log file: $log_file"
    {
        echo "Tshark Output - $stamp"
        echo "Command: ${cmd[*]}"
        echo "----------------------------------------"
    } > "$log_file"

    if [ "$display" = "tee" ]; then
        log_info "Streaming output below (also saved to log)."
        if ! "${cmd[@]}" 2>&1 | tee -a "$log_file"; then
            log_warn "Command exited non-zero. Review: $log_file"
        fi
    else
        ( "${cmd[@]}" >> "$log_file" 2>&1 ) &
        local pid=$!
        progress_bar "$pid" || true
        if ! wait "$pid" 2>/dev/null; then
            log_warn "Command exited non-zero. Review: $log_file"
        fi
    fi

    log_info "Log saved: $log_file"
    LAST_LOG_FILE="$log_file"
    LAST_RUN_STAMP="$stamp"
    record_run_metadata
}

# ============================================================
# Menu option implementations
# ============================================================

# 1. List Available Interfaces
tshark_list_interfaces() {
    LAST_PCAP_FILE=""
    run_tshark interfaces --tee -- tshark -D
}

# 2. Basic Live Capture (packet details)
tshark_basic_capture() {
    local iface
    iface=$(get_interface)
    local count
    read -rp "Packets to capture [100]: " count
    count=${count:-100}
    local stamp
    stamp=$(generate_stamp)
    LAST_PCAP_FILE=""
    run_tshark livecapture --stamp "$stamp" --tee -- \
        tshark -i "$iface" -c "$count"
}

# 3. Capture and Save to PCAP
tshark_capture_to_file() {
    local iface
    iface=$(get_interface)
    local duration
    read -rp "Capture duration in seconds [60]: " duration
    duration=${duration:-60}
    local stamp
    stamp=$(generate_stamp)
    local pcap_file="$LOG_DIR/capture_${stamp}.pcap"
    LAST_PCAP_FILE="$pcap_file"
    run_tshark capture --stamp "$stamp" -- \
        tshark -i "$iface" -a "duration:${duration}" -w "$pcap_file"
    log_info "PCAP saved: $pcap_file"
}

# 4. Read and Display from PCAP
tshark_read_pcap() {
    local pcap_file
    while true; do
        read -rp "Path to PCAP file: " pcap_file
        [ -f "$pcap_file" ] && break
        log_warn "File not found: $pcap_file"
    done
    LAST_PCAP_FILE="$pcap_file"
    run_tshark readpcap --tee -- tshark -r "$pcap_file" -V
}

# 5. Filter HTTP Traffic
tshark_http_filter() {
    local iface
    iface=$(get_interface)
    local count
    read -rp "Packets to capture [200]: " count
    count=${count:-200}
    local stamp
    stamp=$(generate_stamp)
    LAST_PCAP_FILE=""
    run_tshark http --stamp "$stamp" --tee -- \
        tshark -i "$iface" -c "$count" \
            -Y "http" \
            -T fields \
            -e http.request.method \
            -e http.request.uri \
            -e http.response.code \
            -E header=y \
            -E separator='\t'
}

# 6. Filter DNS Queries
tshark_dns_filter() {
    local iface
    iface=$(get_interface)
    local count
    read -rp "Packets to capture [200]: " count
    count=${count:-200}
    local stamp
    stamp=$(generate_stamp)
    LAST_PCAP_FILE=""
    run_tshark dns --stamp "$stamp" --tee -- \
        tshark -i "$iface" -c "$count" \
            -Y "dns" \
            -T fields \
            -e dns.qry.name \
            -e dns.qry.type \
            -E header=y \
            -E separator='\t'
}

# 7. TCP Conversation Statistics
tshark_tcp_stats() {
    local pcap_file
    read -rp "Path to PCAP file (leave blank for live capture): " pcap_file
    if [ -z "$pcap_file" ]; then
        local iface
        iface=$(get_interface)
        local count
        read -rp "Packets for live stats [500]: " count
        count=${count:-500}
        local stamp
        stamp=$(generate_stamp)
        LAST_PCAP_FILE=""
        run_tshark tcpstats --stamp "$stamp" --tee -- \
            tshark -i "$iface" -c "$count" -z conv,tcp -q
    else
        LAST_PCAP_FILE="$pcap_file"
        run_tshark tcpstats --tee -- tshark -r "$pcap_file" -z conv,tcp -q
    fi
}

# 8. Extract Credentials
tshark_extract_creds() {
    local pcap_file
    read -rp "Path to PCAP file (leave blank for live capture): " pcap_file
    if [ -z "$pcap_file" ]; then
        local iface
        iface=$(get_interface)
        local count
        read -rp "Packets for live extraction [500]: " count
        count=${count:-500}
        local stamp
        stamp=$(generate_stamp)
        LAST_PCAP_FILE=""
        run_tshark credentials --stamp "$stamp" --tee -- \
            tshark -i "$iface" -c "$count" -z credentials -q
    else
        LAST_PCAP_FILE="$pcap_file"
        run_tshark credentials --tee -- tshark -r "$pcap_file" -z credentials -q
    fi
}

# 9. Follow TCP Stream (from PCAP)
tshark_follow_stream() {
    local pcap_file
    while true; do
        read -rp "Path to PCAP file: " pcap_file
        [ -f "$pcap_file" ] && break
        log_warn "File not found: $pcap_file"
    done
    LAST_PCAP_FILE="$pcap_file"
    local stream_num
    read -rp "TCP stream number: " stream_num
    run_tshark follow --tee -- \
        tshark -r "$pcap_file" -z "follow,tcp,ascii,${stream_num}" -q
}

# 10. Custom Tshark Command
tshark_custom() {
    local custom_cmd
    while true; do
        read -rp "Custom tshark command: " custom_cmd
        [ -n "$custom_cmd" ] && break
        log_warn "Command cannot be empty."
    done
    local show_output
    read -rp "Stream output to console? (y/n) [n]: " show_output
    LAST_PCAP_FILE=""
    if [[ $show_output =~ ^[Yy]$ ]]; then
        run_tshark custom --tee -- bash -c "$custom_cmd"
    else
        local stamp
        stamp=$(generate_stamp)
        run_tshark custom --stamp "$stamp" -- bash -c "$custom_cmd"
    fi
}

# 11. Install Tshark
# Detects the package manager and installs wireshark-cli (which provides tshark).
# Covers: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL 8+), yum (CentOS/RHEL 7),
#         zypper (openSUSE), pacman (Arch/Manjaro), apk (Alpine), brew (macOS).
tshark_install() {
    if command -v tshark &>/dev/null; then
        log_info "Tshark is already installed: $(tshark --version | head -1)"
        local reinstall
        read -rp "Reinstall/upgrade anyway? (y/n) [n]: " reinstall
        [[ $reinstall =~ ^[Yy]$ ]] || return 0
    fi

    log_info "Detecting package manager..."

    if command -v apt-get &>/dev/null; then
        log_info "Found apt — installing via apt (Debian/Ubuntu/Kali)..."
        # Pre-answer the wireshark debconf prompt so the install is non-interactive.
        # "false" = only root can capture. Change to "true" to allow the wireshark
        # group to capture without sudo.
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        echo "wireshark-common wireshark-common/install-setuid boolean false" \
            | debconf-set-selections
        DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

    elif command -v dnf &>/dev/null; then
        log_info "Found dnf — installing via dnf (Fedora/RHEL 8+/CentOS Stream)..."
        dnf install -y wireshark-cli

    elif command -v yum &>/dev/null; then
        log_info "Found yum — installing via yum (CentOS/RHEL 7)..."
        yum install -y wireshark

    elif command -v zypper &>/dev/null; then
        log_info "Found zypper — installing via zypper (openSUSE/SLES)..."
        zypper install -y wireshark

    elif command -v pacman &>/dev/null; then
        log_info "Found pacman — installing via pacman (Arch/Manjaro)..."
        pacman -Sy --noconfirm wireshark-cli

    elif command -v apk &>/dev/null; then
        log_info "Found apk — installing via apk (Alpine)..."
        apk add --no-cache wireshark

    elif command -v brew &>/dev/null; then
        log_info "Found brew — installing via Homebrew (macOS)..."
        # The wireshark formula installs CLI tools only (no GUI).
        brew install wireshark

    else
        log_error "No supported package manager found (apt, dnf, yum, zypper, pacman, apk, brew). Please install tshark manually from https://www.wireshark.org/download.html"
    fi

    # Confirm success
    if command -v tshark &>/dev/null; then
        log_info "Installation successful: $(tshark --version | head -1)"
    else
        log_error "Installation completed but tshark is still not found. Check the output above for errors."
    fi
}

# --- Menu ---
# Separated into its own function so the loop in main() can reuse it cleanly.
print_menu() {
    echo ""
    log_info "Select scan/analysis type:"
    echo " 1) List Available Interfaces"
    echo " 2) Basic Live Capture"
    echo " 3) Capture and Save to PCAP"
    echo " 4) Read and Display from PCAP"
    echo " 5) Filter HTTP Traffic (Live)"
    echo " 6) Filter DNS Queries (Live)"
    echo " 7) TCP Conversation Statistics"
    echo " 8) Extract Credentials"
    echo " 9) Follow TCP Stream (from PCAP)"
    echo "10) Custom Tshark Command"
    echo "11) Install Tshark"
}

dispatch_choice() {
    local choice="$1"
    # Option 11 bypasses the tshark presence check — it's the installer.
    # All other options require tshark to already be present.
    if [ "$choice" != "11" ]; then
        check_tshark
    fi
    case "$choice" in
        1)  tshark_list_interfaces ;;
        2)  tshark_basic_capture ;;
        3)  tshark_capture_to_file ;;
        4)  tshark_read_pcap ;;
        5)  tshark_http_filter ;;
        6)  tshark_dns_filter ;;
        7)  tshark_tcp_stats ;;
        8)  tshark_extract_creds ;;
        9)  tshark_follow_stream ;;
        10) tshark_custom ;;
        11) tshark_install ;;
        *)  log_warn "Invalid choice '$choice'. Please select 1-11." ;;
    esac
}

# --- Main ---
main() {
    check_root
    while true; do
        print_menu
        local choice
        read -rp "Choice [1-11]: " choice
        dispatch_choice "$choice"
        local another
        read -rp "Run another scan? (y/n): " another
        [[ $another =~ ^[Yy]$ ]] || break
    done
    log_info "--- Script Complete ---"
    log_info "All logs and PCAPs saved in: $LOG_DIR"
}

main "$@"
