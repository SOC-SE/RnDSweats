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
echo -e "\033[0m"
echo "PCAP Analyzer with Tshark - For CCDC Log Filtering"
echo "--------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
LOG_DIR="/var/log/tshark_logs"
mkdir -p "$LOG_DIR"

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# --- Check if Tshark Installed ---
check_tshark() {
    if ! command -v tshark &> /dev/null; then
        log_error "Tshark is not installed. Install Wireshark and try again (e.g., sudo apt install wireshark)."
    fi
    log_info "Tshark detected and ready."
}

# --- Check Directory Access ---
check_dir_access() {
    if [ ! -r "$LOG_DIR" ]; then
        log_error "Cannot read from $LOG_DIR. Run as root or fix permissions (e.g., sudo chown -R $(whoami) $LOG_DIR)."
    fi
    if [ ! -w "$LOG_DIR" ]; then
        log_warn "Cannot write to $LOG_DIR. Some save operations may fail. Run as root or fix permissions."
    fi
}

    local logs=("$LOG_DIR"/*.log)
    local all_files=()
    if [ ${#pcaps[@]} -gt 0 ] || [ ${#logs[@]} -gt 0 ]; then
        if [ ${#pcaps[@]} -gt 0 ]; then
            all_files+=("${pcaps[@]}")
        fi
        if [ ${#logs[@]} -gt 0 ]; then
            all_files+=("${logs[@]}")
        fi
    else
        log_error "No PCAP or LOG files found in $LOG_DIR. Run Network_Scanner_Tshark.sh first."
    fi
    log_info "Available files:"
    local i=1
    for file in "${all_files[@]}"; do
        if [[ "$file" == *.pcap ]]; then
            echo "$i) [PCAP] $(basename "$file")"
        else
            echo "$i) [LOG] $(basename "$file")"
        fi
        ((i++))
    done
    echo "${#all_files[@]}"
}

# --- Get Selected File ---
get_file() {
    local num_files=$(list_files)
    local choice
    read -p "Select file number: " choice
    local all_files=()
    local pcaps=("$LOG_DIR"/*.pcap)
    local logs=("$LOG_DIR"/*.log)
    if [ ${#pcaps[@]} -gt 0 ]; then
        all_files+=("${pcaps[@]}")
    fi
    if [ ${#logs[@]} -gt 0 ]; then
        all_files+=("${logs[@]}")
    fi
    while ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#all_files[@]} ]; do
        log_warn "Invalid selection."
        read -p "Select file number: " choice
    done
    echo "${all_files[$choice-1]}"
}

# --- Run Tshark Filter and Display Table ---
run_pcap_filter() {
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

# --- Run LOG/Text Filter and Display ---
run_log_filter() {
    local log_file=$1
    local pattern=$2
    local headers=$3
    log_info "Applying text filter on $(basename "$log_file"): grep-like for '$pattern'"
    local output=$(grep -i "$pattern" "$log_file" 2>/dev/null || awk -v pat="$pattern" '/'"$pattern"'/ {print}' "$log_file")
    if [ -z "$output" ]; then
        log_warn "No results found for this filter."
        return
    fi
    echo -e "$headers"
    echo "------------------------------------------------------------"
    echo "$output"
    echo "------------------------------------------------------------"
    read -p "Save this output to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/filtered_log_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo -e "$headers\n------------------------------------------------------------\n$output" > "$save_file"
        log_info "Output saved to $save_file"
    fi
}

# --- Filter Functions ---

# 1. Filter HTTP Traffic
filter_http_pcap() {
    local pcap=$1
    run_pcap_filter "$pcap" "http" "-e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code" "Time\tSource IP\tDest IP\tMethod\tURI\tResponse Code"
}

filter_http_log() {
    local log_file=$1
    run_log_filter "$log_file" "HTTP" "Filtered HTTP Lines from Log"
}

# 2. Filter DNS Queries
filter_dns_pcap() {
    local pcap=$1
    run_pcap_filter "$pcap" "dns" "-e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type" "Time\tSource IP\tDest IP\tQuery Name\tQuery Type"
}

filter_dns_log() {
    local log_file=$1
    run_log_filter "$log_file" "DNS" "Filtered DNS Lines from Log"
}

# 3. Filter by Port Number
filter_port_pcap() {
    local pcap=$1
    local port
    read -p "Enter port number (e.g., 80): " port
    while [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; do
        log_warn "Invalid port."
        read -p "Enter port number: " port
    done
    run_pcap_filter "$pcap" "tcp.port == $port or udp.port == $port" "-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto" "Time\tSource IP\tDest IP\tSrc Port\tDst Port\tProtocol"
}

filter_port_log() {
    local log_file=$1
    local port
    read -p "Enter port number (e.g., 80): " port
    while [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; do
        log_warn "Invalid port."
        read -p "Enter port number: " port
    done
    run_log_filter "$log_file" "$port" "Filtered Lines Containing Port $port from Log"
}

# 4. Filter by IP Address
filter_ip_pcap() {
    local pcap=$1
    local ip
    read -p "Enter IP address (e.g., 192.168.1.1): " ip
    while [ -z "$ip" ]; do
        log_warn "IP cannot be empty."
        read -p "Enter IP address: " ip
    done
    run_pcap_filter "$pcap" "ip.src == $ip or ip.dst == $ip" "-e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len" "Time\tSource IP\tDest IP\tProtocol\tLength"
}

filter_ip_log() {
    local log_file=$1
    local ip
    read -p "Enter IP address (e.g., 192.168.1.1): " ip
    while [ -z "$ip" ]; do
        log_warn "IP cannot be empty."
        read -p "Enter IP address: " ip
    done
    run_log_filter "$log_file" "$ip" "Filtered Lines Containing IP $ip from Log"
}

# 5. Filter TCP SYN/ACK (Potential Scans)
filter_tcp_syn_pcap() {
    local pcap=$1
    run_pcap_filter "$pcap" "tcp.flags.syn == 1 or tcp.flags.ack == 1" "-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags" "Time\tSource IP\tDest IP\tSrc Port\tDst Port\tFlags"
}

filter_tcp_syn_log() {
    local log_file=$1
    # Enhanced with regex for SYN or ACK flags
    local output=$(grep -i -E "(tcp\.flags\.syn|tcp\.flags\.ack)" "$log_file" 2>/dev/null || awk '/(SYN|ACK)/ {print}' "$log_file")
    if [ -z "$output" ]; then
        log_warn "No SYN/ACK results found."
        return
    fi
    echo "Filtered SYN/ACK Lines from Log"
    echo "------------------------------------------------------------"
    echo "$output"
    echo "------------------------------------------------------------"
    read -p "Save to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/syn_ack_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo -e "Filtered SYN/ACK Lines\n------------------------------------------------------------\n$output" > "$save_file"
        log_info "Output saved to $save_file"
    fi
}

# 6. Extract Credentials (if any)
filter_creds_pcap() {
    local pcap=$1
    local output=$(tshark -r "$pcap" -z credentials 2>/dev/null)
    if [ -z "$output" ]; then
        log_warn "No credentials found."
        return
    fi
    echo "$output" | column -t
    read -p "Save to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/creds_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo "$output" > "$save_file" 2>/dev/null || log_warn "Save failed - permission issue?"
        log_info "Credentials saved to $save_file"
    fi
}

filter_creds_log() {
    local log_file=$1
    run_log_filter "$log_file" "credentials" "Filtered Credentials Lines from Log"
}

# 7. TCP Conversation Statistics
filter_tcp_stats_pcap() {
    local pcap=$1
    local output=$(tshark -r "$pcap" -z conv,tcp 2>/dev/null)
    if [ -z "$output" ]; then
        log_warn "No TCP stats available."
        return
    fi
    echo "$output" | column -t
    read -p "Save to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/tcp_stats_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo "$output" > "$save_file" 2>/dev/null || log_warn "Save failed - permission issue?"
        log_info "Stats saved to $save_file"
    fi
}

filter_tcp_stats_log() {
    local log_file=$1
    local output=$(grep -A 50 "TCP Conversations" "$log_file" 2>/dev/null || awk '/TCP/ && /Conversations/ {print; getline; while(getline) {if (/^-/) break; print}}' "$log_file")
    if [ -z "$output" ]; then
        log_warn "No TCP stats section found in log."
        return
    fi
    echo "TCP Conversation Statistics from Log"
    echo "------------------------------------------------------------"
    echo "$output" | column -t
    echo "------------------------------------------------------------"
    read -p "Save to file? (y/n): " save
    if [[ $save =~ ^[Yy]$ ]]; then
        local save_file="$LOG_DIR/tcp_stats_log_$(date +"%Y-%m-%d_%H-%M-%S").txt"
        echo -e "TCP Conversation Statistics\n------------------------------------------------------------\n$output" > "$save_file"
        log_info "Stats saved to $save_file"
    fi
}

# 8. Custom Filter
filter_custom() {
    local file=$1
    local custom_filter
    read -p "Enter filter pattern (for PCAP: Tshark filter; for LOG: grep pattern): " custom_filter
    while [ -z "$custom_filter" ]; do
        log_warn "Filter cannot be empty."
        read -p "Enter filter pattern: " custom_filter
    done
    if [[ "$file" == *.pcap ]]; then
        local custom_fields
        read -p "Enter fields to display (e.g., -e frame.time -e ip.src -e ip.dst): " custom_fields
        custom_fields=${custom_fields:-"-e frame.time -e ip.src -e ip.dst -e ip.proto"}
        local custom_headers
        read -p "Enter table headers (tab-separated, e.g., Time\tSource\tDest): " custom_headers
        custom_headers=${custom_headers:-"Time\tSource IP\tDest IP\tProtocol"}
        run_pcap_filter "$file" "$custom_filter" "$custom_fields" "$custom_headers"
    else
        local custom_headers
        read -p "Enter output headers: " custom_headers
        custom_headers=${custom_headers:-"Filtered Lines from Log"}
        run_log_filter "$file" "$custom_filter" "$custom_headers"
    fi
}

# --- Prompt for Filter Mode (Looped) ---
prompt_filter() {
    local file=$1
    local is_pcap=1
    if [[ "$file" != *.pcap ]]; then
        is_pcap=0
    fi
    if [ $is_pcap -eq 1 ]; then
        log_info "Select filter/analysis type for PCAP $(basename "$file"):"
    else
        log_info "Select filter/analysis type for LOG $(basename "$file"):"
    fi
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
        1) if [ $is_pcap -eq 1 ]; then filter_http_pcap "$file"; else filter_http_log "$file"; fi ;;
        2) if [ $is_pcap -eq 1 ]; then filter_dns_pcap "$file"; else filter_dns_log "$file"; fi ;;
        3) if [ $is_pcap -eq 1 ]; then filter_port_pcap "$file"; else filter_port_log "$file"; fi ;;
        4) if [ $is_pcap -eq 1 ]; then filter_ip_pcap "$file"; else filter_ip_log "$file"; fi ;;
        5) if [ $is_pcap -eq 1 ]; then filter_tcp_syn_pcap "$file"; else filter_tcp_syn_log "$file"; fi ;;
        6) if [ $is_pcap -eq 1 ]; then filter_creds_pcap "$file"; else filter_creds_log "$file"; fi ;;
        7) if [ $is_pcap -eq 1 ]; then filter_tcp_stats_pcap "$file"; else filter_tcp_stats_log "$file"; fi ;;
        8) filter_custom "$file" ;;
        9) return 1 ;;  # Back to selection
        10) exit 0 ;;
        *) log_error "Invalid choice. Please select 1-10." ;;
    esac
    return 0  # Continue looping
}

# --- Main Logic ---
main() {
    check_tshark
    check_dir_access
    while true; do
        local file=$(get_file)
        while true; do
            prompt_filter "$file"
            if [ $? -eq 1 ]; then break; fi  # Break inner loop if back selected
            read -p "Apply another filter to this file? (y/n): " again
            if ! [[ $again =~ ^[Yy]$ ]]; then break; fi
        done
        read -p "Analyze another file? (y/n): " another
        if ! [[ $another =~ ^[Yy]$ ]]; then break; fi
    done
    log_info "${GREEN}--- Script Complete ---${NC}"
    log_info "All saved files are in $LOG_DIR. Use for CCDC incident reporting or threat hunting."
}

main "$@"

