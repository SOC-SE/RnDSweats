# ==============================================================================
# File: PCAP_Analyzer_Tshark.sh
# Description: Complementary script to Network_Scanner_Tshark.sh for analyzing saved PCAP files.
#              Reads PCAP files from /tmp/tshark_logs/, allows user to select a file, and apply filters (e.g., HTTP, DNS, ports, IPs).
#              Displays filtered results in a tabular format using Tshark fields. Provides multiple filter options and loops for new filters or exit.
#              Supports threat hunting by extracting specific traffic details for incident reporting. Checks if Tshark is installed.
#              Aligns with Perfect Box Framework (PBF) Moderate (IDS, Log Aggregation) and Advanced (Analysis Tools, SIEM Alerts) categories.
#
# Dependencies: Tshark (from Wireshark package). Install via apt install wireshark or dnf install wireshark.
# Usage: sudo ./PCAP_Analyzer_Tshark.sh
#        Follow on-screen prompts to select PCAP and filter type. Loop allows multiple analyses.
# Notes: 
# - Run as root if needed for file access (though not strictly required for reading PCAPs).
# - In CCDC, use for post-capture analysis without disrupting services. Tables are displayed in console; copy for reports.
# - Custom filters allow flexibility; use Tshark syntax (e.g., 'tcp.port == 80').
# - If no PCAPs found in /tmp/tshark_logs/, notifies and exits.
# ==============================================================================

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
                           _____    ____  _                _      _____ _ _ _            
                          |_   _|  / ___|| |__   __ _ _ __| | __ |  ___(_) | |_ ___ _ __ 
                            | |____\___ \| '_ \ / _` | '__| |/ / | |_  | | | __/ _ \ '__|
                            | |_____|__) | | | | (_| | |  |   <  |  _| | | | ||  __/ |   
                            |_|    |____/|_| |_|\__,_|_|  |_|\_\ |_|   |_|_|\__\___|_|   
EOF  
EOF
echo -e "\033[0m"
echo "PCAP Analyzer with Tshark - For CCDC Log Filtering"
echo "--------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
LOG_DIR="/tmp/tshark_logs"

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function for progress
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "%c " "${spinstr:0:1}"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b"
    done
    printf " \b"
}

# --- Check if Tshark Installed ---
check_tshark() {
    if ! command -v tshark &> /dev/null; then
        log_error "Tshark is not installed. Install Wireshark and try again (e.g., sudo apt install wireshark)."
    fi
    log_info "Tshark detected and ready."
}

# --- List Available PCAP Files ---
list_pcaps() {
    local pcaps=("$LOG_DIR"/*.pcap)
    if [ ${#pcaps[@]} -eq 0 ]; then
        log_error "No PCAP files found in $LOG_DIR. Run Network_Scanner_Tshark.sh first."
    fi
    log_info "Available PCAP files:"
    local i=1
    for pcap in "${pcaps[@]}"; do
        echo "$i) $(basename "$pcap")"
        ((i++))
    done
}

# --- Get Selected PCAP ---
get_pcap() {
    list_pcaps
    local pcaps=("$LOG_DIR"/*.pcap)
    local choice
    read -p "Select PCAP number: " choice
    while ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#pcaps[@]} ]; do
        log_warn "Invalid selection."
        read -p "Select PCAP number: " choice
    done
    echo "${pcaps[$choice-1]}"
}

# --- Run Tshark Filter and Display Table ---
run_filter() {
    local pcap=$1
    local filter=$2
    local fields=$3
    local headers=$4
    log_info "Applying filter on $(basename "$pcap"): $filter"
    log_info "Generating table..."
    local output=$(tshark -r "$pcap" -Y "$filter" -T fields $fields 2>/dev/null)
    if [ -z "$output" ]; then
        log_warn "No results found for this filter."
        return
    fi
    # Display table using column
    echo -e "$headers"
    echo "------------------------------------------------------------"
    echo "$output" | column -t -s $'\t'
    echo "------------------------------------------------------------"
    read -p "Save this table to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/filtered_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo -e "$headers\n------------------------------------------------------------\n$output" > "$save_file"
        log_info "Table saved to $save_file"
    fi
}

# --- Filter Functions ---

# 1. Filter HTTP Traffic
filter_http() {
    local pcap=$1
    run_filter "$pcap" "http" "-e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code" "Time\tSource IP\tDest IP\tMethod\tURI\tResponse Code"
}

# 2. Filter DNS Queries
filter_dns() {
    local pcap=$1
    run_filter "$pcap" "dns" "-e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type" "Time\tSource IP\tDest IP\tQuery Name\tQuery Type"
}

# 3. Filter by Port Number
filter_port() {
    local pcap=$1
    local port
    read -p "Enter port number (e.g., 80): " port
    while [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; do
        log_warn "Invalid port."
        read -p "Enter port number: " port
    done
    run_filter "$pcap" "tcp.port == $port or udp.port == $port" "-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto" "Time\tSource IP\tDest IP\tSrc Port\tDst Port\tProtocol"
}

# 4. Filter by IP Address
filter_ip() {
    local pcap=$1
    local ip
    read -p "Enter IP address (e.g., 192.168.1.1): " ip
    while [ -z "$ip" ]; do
        log_warn "IP cannot be empty."
        read -p "Enter IP address: " ip
    done
    run_filter "$pcap" "ip.src == $ip or ip.dst == $ip" "-e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len" "Time\tSource IP\tDest IP\tProtocol\tLength"
}

# 5. Filter TCP SYN/ACK (Potential Scans)
filter_tcp_syn() {
    local pcap=$1
    run_filter "$pcap" "tcp.flags.syn == 1 or tcp.flags.ack == 1" "-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags" "Time\tSource IP\tDest IP\tSrc Port\tDst Port\tFlags"
}

# 6. Extract Credentials (if any)
filter_creds() {
    local pcap=$1
    local output=$(tshark -r "$pcap" -z credentials 2>/dev/null)
    if [ -z "$output" ]; then
        log_warn "No credentials found."
        return
    fi
    echo "$output"
    read -p "Save to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/creds_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo "$output" > "$save_file"
        log_info "Credentials saved to $save_file"
    fi
}

# 7. TCP Conversation Statistics
filter_tcp_stats() {
    local pcap=$1
    local output=$(tshark -r "$pcap" -z conv,tcp 2>/dev/null)
    echo "$output" | column -t
}

# 8. Custom Filter
filter_custom() {
    local pcap=$1
    local custom_filter
    read -p "Enter Tshark display filter (e.g., 'tcp.port == 80'): " custom_filter
    while [ -z "$custom_filter" ]; do
        log_warn "Filter cannot be empty."
        read -p "Enter Tshark display filter: " custom_filter
    done
    local custom_fields
    read -p "Enter fields to display (e.g., -e frame.time -e ip.src -e ip.dst): " custom_fields
    custom_fields=${custom_fields:-"-e frame.time -e ip.src -e ip.dst -e ip.proto"}
    local custom_headers
    read -p "Enter table headers (tab-separated, e.g., Time\tSource\tDest): " custom_headers
    custom_headers=${custom_headers:-"Time\tSource IP\tDest IP\tProtocol"}
    run_filter "$pcap" "$custom_filter" "$custom_fields" "$custom_headers"
}

# --- Prompt for Filter Mode (Looped) ---
prompt_filter() {
    local pcap=$1
    log_info "Select filter/analysis type for $(basename "$pcap"):"
    echo "1) Filter HTTP Traffic"
    echo "2) Filter DNS Queries"
    echo "3) Filter by Port Number"
    echo "4) Filter by IP Address"
    echo "5) Filter TCP SYN/ACK (Potential Scans)"
    echo "6) Extract Credentials"
    echo "7) TCP Conversation Statistics"
    echo "8) Custom Filter"
    echo "9) Back to PCAP Selection"
    echo "10) Exit"
    read -p "Enter your choice (1-10): " choice
    case "$choice" in
        1) filter_http "$pcap" ;;
        2) filter_dns "$pcap" ;;
        3) filter_port "$pcap" ;;
        4) filter_ip "$pcap" ;;
        5) filter_tcp_syn "$pcap" ;;
        6) filter_creds "$pcap" ;;
        7) filter_tcp_stats "$pcap" ;;
        8) filter_custom "$pcap" ;;
        9) return 1 ;;  # Back to selection
        10) exit 0 ;;
        *) log_error "Invalid choice. Please select 1-10." ;;
    esac
    return 0  # Continue looping
}

# --- Main Logic ---
main() {
    check_tshark
    if [ ! -d "$LOG_DIR" ]; then
        log_error "Log directory $LOG_DIR does not exist. Run Network_Scanner_Tshark.sh first to create PCAP files."
    fi
    while true; do
        local pcap=$(get_pcap)
        while true; do
            prompt_filter "$pcap"
            if [ $? -eq 1 ]; then break; fi  # Break inner loop if back selected
            read -p "Apply another filter to this PCAP? (y/n): " again
            if ! [[ $again =~ ^[Yy]$ ]]; then break; fi
        done
        read -p "Analyze another PCAP? (y/n): " another
        if ! [[ $another =~ ^[Yy]$ ]]; then break; fi
    done
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "All saved files are in $LOG_DIR. Use for CCDC incident reporting or threat hunting."
}

main "$@"