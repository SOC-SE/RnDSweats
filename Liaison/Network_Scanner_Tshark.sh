#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
                     
                                                                                 .::-=++**#####*                     
                                             #####*+-.                  .:=+*##################=                     
                                             .*#########+.        :=*###########*.:###########+                      
                                               +###########*.-*##############################-                       
                                                ###########################################*.                        
                                                -##*#####################################*                           
                                                 ::*###############.#######-..:= :-.- :-                             
                                                =#############+**-#:######..-.... - =-.                              
                                              =###############:#:*:*:*#####-:.---.-.                                 
                                            :#################*.*-#*##########+-:..:.                                
                                           +######################################*:                                 
                                  .+*:    *#######################**###########*:                                    
                      .****:        .- . *######################.+*########*.                                        
                        .-**+.       .. +#*##########:.*######+.*#####+:.. ...                                       
                            =*.     .....-###########=-#####*.:*+-.:-*#+ . .. .:-.                                   
                              .   .+################=:#####:    .######:     :+-                                     
                                     .*###########+::####-       .####+        :--.                                  
                          -*=.         +#######+.  -##*:          :##+     .-+***:                                   
                     ...    :- .**+:   -#####*.   :+:              *-    -+***+:                                     
                     :****+=.    :+*+.  *###*.-=:             .=+.    .+****=.                                       
                        .+****+:   .+*. :###:-**+-.      .   =**.   :****+.   .-+***+.                               
                            :+****:      .##:-*-      :**. .+=.  .=****=    .++:.                                    
                          .-.. .+****-.    =* ==    :***.     .:*****=       ...                                     
                          -++*+.  =*****+-:.     .=*****:..:=*******+     :+*+=:                                     
                               .  :**********************************+:   .                                          
                             .+++******************************************++++++++++======.                      
                                           _____    ____  _                _    
                                          |_   _|  / ___|| |__   __ _ _ __| | __
                                            | |____\___ \| '_ \ / _` | '__| |/ /
                                            | |_____|__) | | | | (_| | |  |   < 
                                            |_|    |____/|_| |_|\__,_|_|  |_|\_\
EOF
echo -e "\033[0m"
echo "Network Scanner with Tshark - For CCDC Threat Hunting"
echo "-----------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
LOG_DIR="/var/log/tshark_logs"
# Ensure the log directory exists for compatibility with PCAP_Analyzer_Tshark.sh
mkdir -p "$LOG_DIR"
if command -v chown >/dev/null 2>&1; then
    chown root:root "$LOG_DIR" 2>/dev/null || true
fi
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Enhanced progress indicator with warning bar
progress_bar() {
    local pid=$1
    local delay=0.2
    local spinstr='|/-\'
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}[WARNING] Scan in progress... Output logged to file.${NC}"
    echo -e "${YELLOW}[WARNING] Press Ctrl+C to stop (for live captures).${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    local timeout=300  # 5 min fallback
    local start=$(date +%s)
    while kill -0 $pid 2>/dev/null; do
        local elapsed=$(( $(date +%s) - start ))
        if [ $elapsed -ge $timeout ]; then
            log_warn "Progress timeout ($timeout s) - assuming complete."
            break
        fi
        local temp=${spinstr#?}
        printf " %c  " "${spinstr:0:1}"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b"  # Adjusted for space
    done
    printf " \b"
    echo -e "\n${GREEN}============================================================${NC}"
    echo -e "${GREEN}[COMPLETE] Scan finished. Check log for details.${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

# TeamPack compliance: confirm authorized environment
teampack_confirm() {
    read -p "Confirm you will run this only on your authorized team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}
teampack_confirm

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root for packet capture."
    fi
}

# --- Check if Tshark Installed ---
check_tshark() {
    if ! command -v tshark &> /dev/null; then
        log_error "Tshark is not installed. Install Wireshark and try again (e.g., sudo apt install wireshark)."
    fi
    log_info "Tshark detected and ready."
}

# --- Get Network Interface ---
get_interface() {
    local iface
    log_info "Available interfaces:"
    tshark -D
    read -p "Enter interface name (e.g., eth0): " iface
    while [ -z "$iface" ]; do
        log_warn "Interface cannot be empty."
        read -p "Enter interface name: " iface
    done
    # Validate
    if ! tshark -D | grep -q "$iface"; then
        log_error "Invalid interface: $iface"
    fi
    echo "$iface"
}

# --- Run Tshark Command with Hidden Output and Logging ---
run_tshark() {
    local cmd=$1
    local log_file="$LOG_DIR/tshark_${TIMESTAMP}.log"
    log_info "Running Tshark command: $cmd"
    log_info "Log saved to: $log_file"
    echo "Tshark Output - $TIMESTAMP" > "$log_file"
    echo "Command: $cmd" >> "$log_file"
    echo "----------------------------------------" >> "$log_file"
    $cmd >> "$log_file" 2>&1 &
    local pid=$!
    progress_bar $pid || true  # Progress bar while running
    wait $pid 2>/dev/null || true
    log_info "Log details available in $log_file"
}

# --- Tshark Functions (Menu Options) ---

# 1. List Available Interfaces
tshark_list_interfaces() {
    run_tshark "tshark -D"
}

# 2. Basic Live Capture (all traffic)
tshark_basic_capture() {
    local iface=$(get_interface)
    local count
    read -p "Enter number of packets to capture (default 100): " count
    count=${count:-100}
    run_tshark "tshark -i $iface -c $count -V"
}

# 3. Capture and Save to PCAP
tshark_capture_to_file() {
    local iface=$(get_interface)
    local duration
    read -p "Enter capture duration in seconds (default 60): " duration
    duration=${duration:-60}
    local pcap_file="$LOG_DIR/capture_${TIMESTAMP}.pcap"
    run_tshark "tshark -i $iface -a duration:$duration -w $pcap_file -V"
    log_info "PCAP saved to $pcap_file"
}

# 4. Read and Display from PCAP
tshark_read_pcap() {
    local pcap_file
    read -p "Enter path to PCAP file: " pcap_file
    while [ ! -f "$pcap_file" ]; do
        log_warn "File not found."
        read -p "Enter path to PCAP file: " pcap_file
    done
    run_tshark "tshark -r $pcap_file -V"
}

# 5. Filter HTTP Traffic (with default packet limit)
tshark_http_filter() {
    local iface=$(get_interface)
    local count
    read -p "Enter number of packets to capture (default 100, for live filter): " count
    count=${count:-100}
    run_tshark "tshark -i $iface -c $count -Y http -T fields -e http.request.method -e http.request.uri -e http.response.code -V"
}

# 6. Filter DNS Queries (with default packet limit)
tshark_dns_filter() {
    local iface=$(get_interface)
    local count
    read -p "Enter number of packets to capture (default 100, for live filter): " count
    count=${count:-100}
    run_tshark "tshark -i $iface -c $count -Y dns -T fields -e dns.qry.name -e dns.qry.type -V"
}

# 7. TCP Conversation Statistics
tshark_tcp_stats() {
    local pcap_file
    read -p "Enter path to PCAP file (or leave blank for live): " pcap_file
    if [ -z "$pcap_file" ]; then
        local iface=$(get_interface)
        local count
        read -p "Enter number of packets for live stats (default 100): " count
        count=${count:-100}
        run_tshark "tshark -i $iface -c $count -z conv,tcp -V"
    else
        run_tshark "tshark -r $pcap_file -z conv,tcp -V"
    fi
}

# 8. Extract Credentials
tshark_extract_creds() {
    local pcap_file
    read -p "Enter path to PCAP file (or leave blank for live): " pcap_file
    if [ -z "$pcap_file" ]; then
        local iface=$(get_interface)
        local count
        read -p "Enter number of packets for live creds extraction (default 100): " count
        count=${count:-100}
        run_tshark "tshark -i $iface -c $count -z credentials -V"
    else
        run_tshark "tshark -r $pcap_file -z credentials -V"
    fi
}

# 9. Follow TCP Stream
tshark_follow_stream() {
    local pcap_file
    read -p "Enter path to PCAP file: " pcap_file
    while [ ! -f "$pcap_file" ]; do
        log_warn "File not found."
        read -p "Enter path to PCAP file: " pcap_file
    done
    local stream_num
    read -p "Enter TCP stream number (from previous analysis): " stream_num
    run_tshark "tshark -r $pcap_file -z follow,tcp,ascii,$stream_num -V"
}

# 10. Custom Tshark Command
tshark_custom() {
    local custom_cmd
    read -p "Enter custom Tshark command (e.g., tshark -i eth0 -Y 'tcp.port == 80'): " custom_cmd
    while [ -z "$custom_cmd" ]; do
        log_warn "Command cannot be empty."
        read -p "Enter custom Tshark command: " custom_cmd
    done
    run_tshark "$custom_cmd"
}

# --- Prompt for Mode ---
prompt_mode() {
    log_info "Select Tshark scan/analysis type:"
    echo "1) List Available Interfaces"
    echo "2) Basic Live Capture"
    echo "3) Capture and Save to PCAP"
    echo "4) Read and Display from PCAP"
    echo "5) Filter HTTP Traffic (Live)"
    echo "6) Filter DNS Queries (Live)"
    echo "7) TCP Conversation Statistics"
    echo "8) Extract Credentials"
    echo "9) Follow TCP Stream (from PCAP)"
    echo "10) Custom Tshark Command"
    read -p "Enter your choice (1-10): " choice
    case "$choice" in
        1) tshark_list_interfaces ;;
        2) tshark_basic_capture ;;
        3) tshark_capture_to_file ;;
        4) tshark_read_pcap ;;
        5) tshark_http_filter ;;
        6) tshark_dns_filter ;;
        7) tshark_tcp_stats ;;
        8) tshark_extract_creds ;;
        9) tshark_follow_stream ;;
        10) tshark_custom ;;
        *) log_error "Invalid choice. Please select 1-10." ;;
    esac
}

# --- Main Logic ---
main() {
    check_root
    check_tshark
    while true; do
        prompt_mode
        read -p "Run another scan? (y/n): " another
        if ! [[ $another =~ ^[Yy]$ ]]; then break; fi
    done
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "All logs and PCAPs are saved in $LOG_DIR. Use for CCDC incident reporting or threat hunting."
}

main "$@"