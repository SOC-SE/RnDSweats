#!/bin/bash
#
#   masterEnum.sh
#   
#   This script is an amalgamation of several ideas, scripts, and small personal tools I've built up.
#   This run and system audit and outputs it to a log file.
#
#   A thank you to CyberUCI and Windserpent. Several scripts of theirs were used and adapted for this script.
#
#   https://github.com/cyberuci
#   https://github.com/windserpent
#
#
#   Samuel Brucker 2025-2026
#

set -u pipefail 


# Ensure we are root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root." 
   exit 1
fi

# Grab the hostname
HOSTNAME=$(hostname || cat /etc/hostname)

# Global Config
mkdir -p /var/log/syst/
# UPDATED: Added _%H%M to the filename for hour/minute granularity
LOG_FILE="/var/log/syst/${HOSTNAME}_audit_$(date +%Y%m%d_%H%M).log"
ENABLE_LOGGING=true

# Unified Logging Function
log() {
    # UPDATED: Removed timestamp. Now acts as a simple append.
    # Was: local msg="$(date '+%Y-%m-%d %H:%M:%S') - $1"
    local msg="[PROGRESS] - $1"
    echo "$msg" >> "$LOG_FILE"
}

error_exit() {
    local msg="CRITICAL SECURITY AUDIT ERROR: $1"
    
    # 1. Write to the log file
    echo "ERROR: $1" >&2
    log "$msg"
    
    # 2. Broadcast to all logged-in users
    # (Only works if running as root, which this script requires anyway)
    echo "$msg" | wall
    
    exit 1
}

get_inventory(){
    # --- Local Helper Functions ---
    empty_line () {
        echo ""
    }

    command_exists() {
        command -v "$1" > /dev/null 2>&1
    }

    stringContain() { case $2 in *$1* ) return 0;; *) return 1;; esac ;}

    # RENAMED to avoid conflict with your main get_users module
    get_group_members() {
       grep "^$1:" /etc/group | cut -d: -f4 | tr ',' '\n'
    }

    # --- Gathering Variables ---
    # We use local variables where possible to be safe
    local HOSTNAME=$(hostname || cat /etc/hostname)
    local IP_ADDR=$( ( ip a | grep -oE '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/[[:digit:]]{1,2}' | grep -v '127.0.0.1' ) || ( ifconfig | grep -oE 'inet.+([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' | grep -v '127.0.0.1' ) )
    local OS=$( (hostnamectl | grep "Operating System" | cut -d: -f2) || (cat /etc/*-release  | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//' | sed 's/"//g') )

    # --- Output ---
    echo "System Inventory - Security Assessment"
    echo "======================================"
    
    empty_line
    echo -e "$HOSTNAME Summary"
    empty_line

    printf "Hostname: "
    echo -e $HOSTNAME
    empty_line

    printf "IP Address: "
    echo -e $IP_ADDR
    empty_line

    printf "Script User: "
    echo -e $USER
    empty_line

    printf "Operating System: "
    echo -e $OS
    empty_line

    echo "Hardware Resources:"
    
    # CPU Information
    if command_exists lscpu; then
        local cpu_model=$(lscpu | grep "Model name:" | sed 's/Model name:[ \t]*//')
        local cpu_cores=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
    else
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2 | sed 's/^[ \t]*//')
        local cpu_cores=$(grep -c ^processor /proc/cpuinfo)
    fi

    printf "CPU Model: "
    echo "$cpu_model"
    printf "CPU Cores: "
    echo "$cpu_cores"

    # RAM Information
    if command_exists free; then
        local ram_total=$(free -m | awk '/Mem:/ {print $2}')
        printf "Total RAM: "
        echo "${ram_total} MB"
    else
        echo "RAM: Unable to determine (free command missing)"
    fi

    empty_line

    # Storage Information
    echo "Storage Devices:"
    if command_exists lsblk; then
        # List physical disks only (no partitions/loops)
        lsblk -d -o NAME,SIZE,MODEL,TYPE | grep -v "loop"
    else
        # Fallback to df if lsblk is missing
        df -h --output=source,size,target -x tmpfs -x devtmpfs
    fi
    empty_line


    if command -v transactional-update; then
        echo "Transactional Server - This is an immutable Linux distribution"
        transactional-update status
        empty_line
    fi

    echo "Open ports and PIDs:"
    if command_exists ss; then
        ss -tulpn | sort -k 1,1 -k 2,2 | awk 'NR==1; NR>1{print | "sort -V -k 4,4"}' | sed '1 s/Process/Process                     /'
    elif command_exists sockstat; then
        sockstat -4
    elif command_exists netstat; then
        netstat -an | grep LISTEN
    elif command_exists lsof; then
        lsof -i -P -n | grep LISTEN
    else
        echo "required tools for this section not found"
    fi

    empty_line
    echo "Running Container information:"

    if ! command_exists docker; then
        echo "Docker command not found. Skipping..."
    else
        running_container_info=$(docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}")

        if [ -z "$running_container_info" ]; then
            echo "No running containers found."
        else
            printf "%-34s %-40s %-30s\n" "Container Name" "Internal Ports" "External Ports"

            echo "$running_container_info" | while IFS=$'\t' read -r container_name status ports; do
            if ! stringContain "(Paused)" "$status"; then
                    # Extract internal and external ports
                    internal_ports=$(echo "$ports" | awk -F '->' '{print $1}' | tr ',' '\n' | awk -F '/' '{print $1}' | tr '\n' ',')
                    external_ports=$(echo "$ports" | awk -F '->' '{print $2}' | awk -F ',' '{print $1}' | tr '\n' ',')

                    # Remove trailing commas
                    internal_ports=$(echo "$internal_ports" | sed 's/,$//')
                    external_ports=$(echo "$external_ports" | sed 's/,$//')
            
            if [ -z "$internal_ports" ]; then
                internal_ports="N/A"
            fi

            if [ -z "$external_ports" ]; then
                external_ports="N/A"
            fi
                    # Print container information with consistent spacing
                    printf "[+] %-30s %-40s %-30s\n" "$container_name" "$internal_ports" "$external_ports"
                fi
            done
        fi

        echo
        echo "Non-Running Container information:"

        # Get non-running container information
        non_running_container_info=$(docker ps -a --filter "status=exited" --filter "status=paused" --filter "status=dead" --filter "status=restarting" --format "{{.Names}}\t{{.Status}}")

        # Check if there are non-running containers
        if [ -z "$non_running_container_info" ]; then
            echo "No non-running containers found."
        else
            # Print header for non-running containers
            printf "%-34s %-30s\n" "Container Name" "Status"

            # Iterate over each non-running container and print information
            echo "$non_running_container_info" | while IFS=$'\t' read -r container_name status; do
                # Print container information with consistent spacing
                printf "[-] %-30s %-30s\n" "$container_name" "$status"
            done
        fi
    fi

    empty_line
    echo "Human users"
    awk -F: '{if (($3 >= 1000 || $1 == "root") && $1 != "nobody") printf "Username: %-15s UID: %-5s Home: %-20s Shell: %s\n", $1, $3, $6, $7}' /etc/passwd
    empty_line

    echo "Admin users (sudo or wheel):"
    # UPDATED: Calling the local helper function, NOT the global module
    get_group_members sudo
    get_group_members wheel
    empty_line

    if [ -e "/etc/krb5.conf" ]; then
        echo "MACHINE IS DOMAIN JOINED"
        printf "Domain: "
        grep -o "^.*default_realm.*=.*" /etc/krb5.conf | awk '{print $3}'
        empty_line
    else
        echo "MACHINE IS NOT DOMAIN JOINED"
        echo "NO DOMAIN"
        empty_line
    fi

    echo "MOUNTS:"
    grep -v '^#' /etc/fstab
    empty_line

    echo "Processes possibly tied to services:"
    ps aux | awk 'NR==1; /docker|samba|postfix|dovecot|smtp|psql|ssh|clamav|mysql|bind9|apache|smbfs|samba|openvpn|splunk|nginx|mysql|mariadb|ftp|slapd|amavisd|wazuh/ && !/awk/ {print $0}' | grep -v "grep"
    empty_line

    if command -v kubectl; then
        echo "KUBERNETES:"
        k=$(kubectl get nodes $HOSTNAME 2>/dev/null | grep "control-plane")
        if [ -z "$k" ]; then
            echo "THIS IS A KUBERNETES WORKER NODE"
        else
            echo "THIS IS A KUBERNETES CONTROL PLANE NODE"
            kubectl get nodes -o wide
        fi
    else
        echo "KUBERNETES NOT INSTALLED"
    fi
}

get_cron() {

    local USER_WIDTH=12
    local SCHEDULE_WIDTH=17
    local COMMAND_WIDTH=50
    local FLAGS_WIDTH=25

    # Arrays to store cron jobs by category
    declare -a suspicious_jobs
    declare -a system_jobs
    declare -a user_jobs

    is_high_frequency() {
        local schedule="$1"
        # Check for patterns like "* * * * *" or "*/1 * * * *"
        [[ "$schedule" =~ ^\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\* ]] || \
        [[ "$schedule" =~ ^\*/1[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\* ]]
    }

    # Check if command contains suspicious patterns
    is_suspicious_command() {
        local command="$1"
        local -a suspicious_patterns=(
            # Network commands
            "wget" "curl" "nc" "netcat" "telnet" "ssh" "scp" "rsync"
            # Temporary directories
            "/tmp/" "/var/tmp/" "/dev/shm/"
            # Encoded content
            "base64" "echo.*|.*base64" "python.*-c" "perl.*-e"
            # Reverse shells
            "/dev/tcp/" "bash.*-i" "sh.*-i"
            # Privilege escalation
            "chmod.*777" "chown.*root" "sudo" "su -"
            # Suspicious locations
            "/dev/null.*&" "nohup"
        )
        
        for pattern in "${suspicious_patterns[@]}"; do
            if [[ "$command" =~ $pattern ]]; then
                return 0
            fi
        done
        return 1
    }

    # Get flag description for suspicious jobs
    get_suspicious_flags() {
        local schedule="$1"
        local command="$2"
        local flags=""
        
        if is_high_frequency "$schedule"; then
            flags+="[HIGH-FREQ] "
        fi
        
        # Check specific suspicious patterns
        if [[ "$command" =~ (wget|curl) ]]; then
            flags+="[NETWORK-DL] "
        elif [[ "$command" =~ (nc|netcat|telnet) ]]; then
            flags+="[NETWORK-CONN] "
        elif [[ "$command" =~ /tmp/|/var/tmp/|/dev/shm/ ]]; then
            flags+="[TEMP-DIR] "
        elif [[ "$command" =~ base64|python.*-c|perl.*-e ]]; then
            flags+="[ENCODED] "
        elif [[ "$command" =~ /dev/tcp/|bash.*-i|sh.*-i ]]; then
            flags+="[REVERSE-SHELL] "
        elif [[ "$command" =~ chmod.*777|chown.*root ]]; then
            flags+="[PRIVESC] "
        fi
        
        if [[ -n "$flags" ]]; then
            echo "[SUSPICIOUS] ${flags%% }"
        else
            echo "[SUSPICIOUS]"
        fi
    }

    # Parse system cron files
    parse_system_crons() {
        log "Parsing system cron files"
        
        # Check /etc/crontab
        if [[ -f /etc/crontab ]]; then
            while read -r line; do
                # Skip comments and empty lines
                [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
                # Skip variable assignments
                [[ "$line" =~ ^[[:space:]]*[A-Z_]+=.* ]] && continue
                
                # Parse crontab line: min hour day month dow user command
                if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*) ]]; then
                    local schedule="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]} ${BASH_REMATCH[5]}"
                    local user="${BASH_REMATCH[6]}"
                    local command="${BASH_REMATCH[7]}"
                    
                    if is_suspicious_command "$command" || is_high_frequency "$schedule"; then
                        local flags
                        flags=$(get_suspicious_flags "$schedule" "$command")
                        suspicious_jobs+=("$user|$schedule|$command|$flags")
                    else
                        system_jobs+=("$user|$schedule|$command|System cron")
                    fi
                fi
            done < /etc/crontab
        fi
        
        # Check /etc/cron.d/
        if [[ -d /etc/cron.d ]]; then
            for cronfile in /etc/cron.d/*; do
                [[ -f "$cronfile" ]] || continue
                while read -r line; do
                    [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
                    [[ "$line" =~ ^[[:space:]]*[A-Z_]+=.* ]] && continue
                    
                    if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*) ]]; then
                        local schedule="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]} ${BASH_REMATCH[5]}"
                        local user="${BASH_REMATCH[6]}"
                        local command="${BASH_REMATCH[7]}"
                        
                        if is_suspicious_command "$command" || is_high_frequency "$schedule"; then
                            local flags
                            flags=$(get_suspicious_flags "$schedule" "$command")
                            suspicious_jobs+=("$user|$schedule|$command|$flags")
                        else
                            system_jobs+=("$user|$schedule|$command|cron.d: $(basename "$cronfile")")
                        fi
                    fi
                done < "$cronfile"
            done
        fi
        
        # Check simplified cron directories
        for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
            if [[ -d "$crondir" ]]; then
                for cronscript in "$crondir"/*; do
                    [[ -f "$cronscript" && -x "$cronscript" ]] || continue
                    local schedule=""
                    local user="root"
                    local command="$cronscript"
                    
                    case "$crondir" in
                        */cron.hourly)  schedule="0 * * * *" ;;
                        */cron.daily)   schedule="0 2 * * *" ;;
                        */cron.weekly)  schedule="0 3 * * 0" ;;
                        */cron.monthly) schedule="0 4 1 * *" ;;
                    esac
                    
                    if is_suspicious_command "$command"; then
                        local flags
                        flags=$(get_suspicious_flags "$schedule" "$command")
                        suspicious_jobs+=("$user|$schedule|$command|$flags")
                    else
                        system_jobs+=("$user|$schedule|$command|$(basename "$crondir")")
                    fi
                done
            fi
        done
    }

    # Parse user crontabs
    parse_user_crons() {
        log "Parsing user crontabs"
        
        # Get list of users with potential crontabs
        while IFS=: read -r username _ uid _ _ home shell; do
            # Skip system accounts without login shells for efficiency
            [[ "$uid" -ge 1000 || "$shell" =~ (bash|sh|zsh|fish)$ ]] || continue
            
            # Try to read user's crontab
            local user_cron_output
            if user_cron_output=$(crontab -u "$username" -l 2>/dev/null); then
                while read -r line; do
                    [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
                    
                    # Parse user crontab line: min hour day month dow command
                    if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*) ]]; then
                        local schedule="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]} ${BASH_REMATCH[5]}"
                        local command="${BASH_REMATCH[6]}"
                        
                        if is_suspicious_command "$command" || is_high_frequency "$schedule"; then
                            local flags
                            flags=$(get_suspicious_flags "$schedule" "$command")
                            suspicious_jobs+=("$username|$schedule|$command|$flags")
                        else
                            user_jobs+=("$username|$schedule|$command|User crontab")
                        fi
                    fi
                done <<< "$user_cron_output"
            fi
        done < /etc/passwd
    }

    # Parse systemd timers (if available)
    parse_systemd_timers() {
        log "Parsing systemd timers"
        
        # Check if systemctl is available
        if ! command -v systemctl >/dev/null 2>&1; then
            return
        fi
        
        # Get list of timer units
        while read -r timer_line; do
            [[ -n "$timer_line" ]] || continue
            
            local timer_name
            timer_name=$(echo "$timer_line" | awk '{print $1}')
            [[ "$timer_name" =~ \.timer$ ]] || continue
            
            # Get timer schedule and associated service
            local schedule="systemd-timer"
            local service_name="${timer_name%.timer}.service"
            local command="systemctl start $service_name"
            local user="root"
            
            # Basic check for suspicious service names
            if [[ "$timer_name" =~ (backup|update|clean).*\.timer$ ]]; then
                system_jobs+=("$user|$schedule|$command|SystemD timer")
            else
                # Flag unusual timer names as potentially suspicious
                suspicious_jobs+=("$user|$schedule|$command|[SUSPICIOUS] Unusual timer name")
            fi
            
        done < <(systemctl list-timers --no-pager --no-legend --all 2>/dev/null | grep -E "\.timer")
    }

    # Function to print section header
    print_header() {
        local title="$1"
        
        echo
        echo "=== $title ==="
        printf "%-${USER_WIDTH}s %-${SCHEDULE_WIDTH}s %-${COMMAND_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "USER" "SCHEDULE" "COMMAND" "FLAGS"
        printf "%-${USER_WIDTH}s %-${SCHEDULE_WIDTH}s %-${COMMAND_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "$(printf '%*s' 4 | tr ' ' '-')" \
            "$(printf '%*s' 8 | tr ' ' '-')" \
            "$(printf '%*s' 7 | tr ' ' '-')" \
            "$(printf '%*s' 5 | tr ' ' '-')"
    }

    # Function to print cron jobs from array
    print_cron_jobs() {
        local -n jobs_array=$1
        
        for job_entry in "${jobs_array[@]}"; do
            IFS='|' read -r user schedule command flags <<< "$job_entry"
            printf "%-${USER_WIDTH}s %-${SCHEDULE_WIDTH}s %-${COMMAND_WIDTH}s %-${FLAGS_WIDTH}s\n" \
                "$user" \
                "$schedule" \
                "${command:0:$((COMMAND_WIDTH-1))}" \
                "$flags"
        done
    }

    # Function to sort cron jobs by user, then by schedule
    sort_cron_jobs() {
        local -n jobs_array=$1
        local temp_file=$(mktemp)
        
        # Create sortable entries
        for job_entry in "${jobs_array[@]}"; do
            IFS='|' read -r user schedule command flags <<< "$job_entry"
            echo "${user}|${schedule}|${job_entry}" >> "$temp_file"
        done
        
        # Sort by user, then by schedule
        jobs_array=()
        while IFS='|' read -r user schedule original_entry; do
            jobs_array+=("$original_entry")
        done < <(sort -t'|' -k1,1 -k2,2 "$temp_file")
        
        rm "$temp_file"
    }

    # Main enumeration function
    enumerate_cron_jobs() {
        echo "Cron Job Enumeration - Security Assessment"
        echo "=========================================="
        
        parse_system_crons
        parse_user_crons
        parse_systemd_timers
        
        # Sort arrays
        sort_cron_jobs suspicious_jobs
        sort_cron_jobs system_jobs
        sort_cron_jobs user_jobs
        
        # Print Suspicious Cron Jobs section
        print_header "Suspicious Cron Jobs"
        if [[ ${#suspicious_jobs[@]} -eq 0 ]]; then
            echo "No suspicious cron jobs found."
        else
            print_cron_jobs suspicious_jobs
        fi
        
        # Print System Cron Jobs section  
        print_header "System Cron Jobs"
        if [[ ${#system_jobs[@]} -eq 0 ]]; then
            echo "No system cron jobs found."
        else
            print_cron_jobs system_jobs
        fi
        
        # Print User Cron Jobs section
        print_header "User Cron Jobs"
        if [[ ${#user_jobs[@]} -eq 0 ]]; then
            echo "No user cron jobs found."
        else
            print_cron_jobs user_jobs
        fi
        
        echo
        echo "Summary:"
        echo "  Suspicious jobs: ${#suspicious_jobs[@]}"
        echo "  System jobs: ${#system_jobs[@]}"
        echo "  User jobs: ${#user_jobs[@]}"
        
        log "Cron job enumeration completed - Suspicious: ${#suspicious_jobs[@]}, System: ${#system_jobs[@]}, User: ${#user_jobs[@]}"
    }

    #Execute the cron grabbing
    enumerate_cron_jobs

}

get_users(){

    local USERNAME_WIDTH=20
    local UID_WIDTH=8
    local GROUPS_WIDTH=16
    local SHELL_WIDTH=20
    local HOME_WIDTH=20
    local FLAGS_WIDTH=20

    # Flag details column configuration
    local FLAG_DETAIL_FLAG_WIDTH=15
    local FLAG_DETAIL_USERNAME_WIDTH=20
    local FLAG_DETAIL_UID_WIDTH=8
    local FLAG_DETAIL_REASON_WIDTH=50

    # Arrays to store users by category
    declare -a high_risk_users
    declare -a privileged_users  
    declare -a standard_users

    # Array to store flag details
    declare -a flag_details


    check_system() {
        if [[ ! -f /etc/passwd ]] || [[ ! -f /etc/shadow ]] || [[ ! -f /etc/group ]]; then
            error_exit "Required system files not found"
        fi
        
        # Check if we can read shadow file (requires root for password checks)
        if [[ $EUID -eq 0 ]] && [[ -r /etc/shadow ]]; then
            SHADOW_READABLE=true
        else
            SHADOW_READABLE=false
            echo "Warning: Running without root privileges - password checks disabled"
        fi
        
        log "System check passed - user enumeration starting"
    }

    # Check if user has empty/locked password
    has_empty_password() {
        local username="$1"
        
        if [[ "$SHADOW_READABLE" == "false" ]]; then
            return 1
        fi
        
        local password_hash
        password_hash=$(getent shadow "$username" | cut -d: -f2)
        
        # Empty password or locked account patterns
        [[ -z "$password_hash" ]] || [[ "$password_hash" == "!" ]] || [[ "$password_hash" == "*" ]]
    }

    # Check if user was created recently (last 30 days)
    is_recent_user() {
        local username="$1"
        local home_dir="$2"
        
        # Check if home directory was created in last 30 days
        if [[ -d "$home_dir" ]]; then
            local dir_age
            dir_age=$(find "$home_dir" -maxdepth 0 -mtime -30 2>/dev/null | wc -l)
            [[ "$dir_age" -gt 0 ]]
        else
            return 1
        fi
    }

    # Add flag detail entry
    add_flag_detail() {
        local flag="$1"
        local username="$2" 
        local uid="$3"
        local reason="$4"
        
        flag_details+=("$flag|$username|$uid|$reason")
    }

    # Categorize users based on security risk
    categorize_users() {
        log "Categorizing users by security risk level"
        
        # Read /etc/passwd and analyze each user
        while IFS=: read -r username password uid gid gecos home shell; do
            local groups user_groups flags_list=() primary_flag=""
            
            # Get user's groups
            user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | sed 's/^ *//; s/ /, /g' || echo "")
            
            # Determine user category and collect flags
            local is_high_risk=false
            
            # Check for high-risk conditions
            if [[ "$uid" -eq 0 && "$username" != "root" ]]; then
                # Non-root user with UID 0 - HIGH RISK
                flags_list+=("[SUSPICIOUS]")
                add_flag_detail "[SUSPICIOUS]" "$username" "$uid" "Non-root UID 0"
                is_high_risk=true
                
            elif [[ "$uid" -lt 1000 && "$shell" =~ /(bash|sh|zsh|fish)$ ]]; then
                # Service account with login shell - HIGH RISK
                flags_list+=("[SUSPICIOUS]")
                add_flag_detail "[SUSPICIOUS]" "$username" "$uid" "Service account with login shell"
                is_high_risk=true
                
            elif has_empty_password "$username"; then
                # Empty password - HIGH RISK
                flags_list+=("[SUSPICIOUS]")
                add_flag_detail "[SUSPICIOUS]" "$username" "$uid" "Empty/locked password"
                is_high_risk=true
            fi
            
            # Check for recent user (can be combined with suspicious)
            if is_recent_user "$username" "$home"; then
                flags_list+=("[RECENT]")
                add_flag_detail "[RECENT]" "$username" "$uid" "Created within 30 days"
                is_high_risk=true
            fi
            
            # Build flags display string
            if [[ ${#flags_list[@]} -gt 0 ]]; then
                primary_flag=$(IFS=', '; echo "${flags_list[*]}")
            fi
            
            # Categorize the user
            if [[ "$is_high_risk" == "true" ]]; then
                high_risk_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
                
            elif echo "$user_groups" | grep -qE "(wheel|sudo|admin|root)"; then
                # User has administrative privileges
                primary_flag="Admin user"
                privileged_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
                
            elif [[ "$uid" -ge 1000 && "$shell" =~ /(bash|sh|zsh|fish)$ ]]; then
                # Regular user account
                primary_flag="Regular user"
                standard_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
                
            elif [[ "$uid" -lt 1000 ]]; then
                # System account with nologin shell (normal)
                primary_flag="System account"
                standard_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
            fi
            
        done < /etc/passwd
    }

    # Function to print section header
    print_header() {
        local title="$1"
        
        echo
        echo "=== $title ==="
        printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "USERNAME" "UID" "GROUPS" "SHELL" "HOME" "FLAGS"
        printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "$(printf '%*s' 8 | tr ' ' '-')" \
            "$(printf '%*s' 3 | tr ' ' '-')" \
            "$(printf '%*s' 6 | tr ' ' '-')" \
            "$(printf '%*s' 5 | tr ' ' '-')" \
            "$(printf '%*s' 4 | tr ' ' '-')" \
            "$(printf '%*s' 5 | tr ' ' '-')"
    }

    # Function to print users from array
    print_users() {
        local -n users_array=$1
        
        for user_entry in "${users_array[@]}"; do
            IFS='|' read -r username uid groups shell home flags <<< "$user_entry"
            printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${FLAGS_WIDTH}s\n" \
                "$username" \
                "$uid" \
                "${groups:0:$((GROUPS_WIDTH-1))}" \
                "$shell" \
                "${home:0:$((HOME_WIDTH-1))}" \
                "$flags"
        done
    }

    # Function to print flag details section
    print_flag_details() {
        echo
        echo "=== Flag Details ==="
        printf "%-${FLAG_DETAIL_FLAG_WIDTH}s %-${FLAG_DETAIL_USERNAME_WIDTH}s %-${FLAG_DETAIL_UID_WIDTH}s %-${FLAG_DETAIL_REASON_WIDTH}s\n" \
            "FLAG" "USERNAME" "UID" "REASON"
        printf "%-${FLAG_DETAIL_FLAG_WIDTH}s %-${FLAG_DETAIL_USERNAME_WIDTH}s %-${FLAG_DETAIL_UID_WIDTH}s %-${FLAG_DETAIL_REASON_WIDTH}s\n" \
            "$(printf '%*s' 4 | tr ' ' '-')" \
            "$(printf '%*s' 8 | tr ' ' '-')" \
            "$(printf '%*s' 3 | tr ' ' '-')" \
            "$(printf '%*s' 6 | tr ' ' '-')"
        
        if [[ ${#flag_details[@]} -eq 0 ]]; then
            echo "No flags to detail."
        else
            # Sort flag details by flag type, then by username
            local temp_file=$(mktemp)
            for detail_entry in "${flag_details[@]}"; do
                IFS='|' read -r flag username uid reason <<< "$detail_entry"
                case "$flag" in
                    "[SUSPICIOUS]") echo "1|${flag}|${username}|${uid}|${reason}" >> "$temp_file" ;;
                    "[RECENT]")     echo "2|${flag}|${username}|${uid}|${reason}" >> "$temp_file" ;;
                    *)              echo "9|${flag}|${username}|${uid}|${reason}" >> "$temp_file" ;;
                esac
            done
            
            local -a sorted_details
            while IFS='|' read -r priority flag username uid reason; do
                sorted_details+=("$flag|$username|$uid|$reason")
            done < <(sort -t'|' -k1,1n -k4,4n "$temp_file")
            
            for detail_entry in "${sorted_details[@]}"; do
                IFS='|' read -r flag username uid reason <<< "$detail_entry"
                printf "%-${FLAG_DETAIL_FLAG_WIDTH}s %-${FLAG_DETAIL_USERNAME_WIDTH}s %-${FLAG_DETAIL_UID_WIDTH}s %-${FLAG_DETAIL_REASON_WIDTH}s\n" \
                    "$flag" "$username" "$uid" "$reason"
            done
            
            rm "$temp_file"
        fi
    }

    # Function to sort users by UID
    sort_users_by_uid() {
        local -n users_array=$1
        local temp_file=$(mktemp)
        
        # Create sortable entries
        for user_entry in "${users_array[@]}"; do
            IFS='|' read -r username uid rest <<< "$user_entry"
            echo "${uid}|${user_entry}" >> "$temp_file"
        done
        
        # Sort by UID (numerical), then extract original entries
        users_array=()
        while IFS='|' read -r uid original_entry; do
            users_array+=("$original_entry")
        done < <(sort -t'|' -k1,1n "$temp_file")
        
        rm "$temp_file"
    }

    # Main enumeration function
    enumerate_users() {
        echo "User Enumeration - Security Assessment"
        echo "====================================="
        
        categorize_users
        
        # Sort arrays
        sort_users_by_uid high_risk_users
        sort_users_by_uid privileged_users
        sort_users_by_uid standard_users
        
        # Print High-Risk Users section
        print_header "High-Risk/Suspicious Users"
        if [[ ${#high_risk_users[@]} -eq 0 ]]; then
            echo "No high-risk users found."
        else
            print_users high_risk_users
        fi
        
        # Print Privileged Users section  
        print_header "Privileged Users"
        if [[ ${#privileged_users[@]} -eq 0 ]]; then
            echo "No privileged users found."
        else
            print_users privileged_users
        fi
        
        # Print Standard Users section
        print_header "Standard Users"
        if [[ ${#standard_users[@]} -eq 0 ]]; then
            echo "No standard users found."
        else
            print_users standard_users
        fi
        
        # Print flag details section
        print_flag_details
        
        echo
        echo "Summary:"
        echo "  High-risk users: ${#high_risk_users[@]}"
        echo "  Privileged users: ${#privileged_users[@]}"
        echo "  Standard users: ${#standard_users[@]}"
        echo "  Total flags: ${#flag_details[@]}"
        
        log "User enumeration completed - High-risk: ${#high_risk_users[@]}, Privileged: ${#privileged_users[@]}, Standard: ${#standard_users[@]}, Flags: ${#flag_details[@]}"


        #Execute grabbing the users
        check_system
        enumerate_users
    }
}

get_sudoers(){

    # Column width configuration
    local ENTITY_WIDTH=10
    local TYPE_WIDTH=6
    local PERMISSIONS_WIDTH=25
    local COMMANDS_WIDTH=25
    local FLAGS_WIDTH=40

    # Arrays to store sudoers entries by category
    declare -a high_risk_rules
    declare -a group_privileges
    declare -a user_privileges

    # Check if command list contains dangerous commands (based on GTFOBins Sudo category)
    # Source: https://gtfobins.github.io/
    contains_dangerous_commands() {
        local commands="$1"
        local -a dangerous_cmds=(
            "7z" "aa-exec" "ab" "alpine" "ansible-playbook" "ansible-test" "aoss" "apache2ctl" "apt-get" 
            "apt" "ar" "aria2c" "arj" "arp" "as" "ascii-xfr" "ascii85" "ash" "aspell" "at" "atobm" "awk" 
            "aws" "base32" "base58" "base64" "basenc" "basez" "bash" "batcat" "bc" "bconsole" "bpftrace" 
            "bridge" "bundle" "bundler" "busctl" "busybox" "byebug" "bzip2" "c89" "c99" "cabal" "capsh" 
            "cat" "cdist" "certbot" "check_by_ssh" "check_cups" "check_log" "check_memory" "check_raid" 
            "check_ssl_cert" "check_statusfile" "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "cobc" 
            "column" "comm" "composer" "cowsay" "cowthink" "cp" "cpan" "cpio" "cpulimit" "crash" "crontab" 
            "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dc" "dd" "debugfs" "dialog" 
            "diff" "dig" "distcc" "dmesg" "dmidecode" "dmsetup" "dnf" "docker" "dosbox" "dotnet" "dpkg" 
            "dstat" "dvips" "easy_install" "eb" "ed" "efax" "elvish" "emacs" "enscript" "env" "eqn" 
            "espeak" "ex" "exiftool" "expand" "expect" "facter" "file" "find" "fping" "ftp" "gawk" "gcc" 
            "gcloud" "gcore" "gdb" "gem" "genie" "genisoimage" "ghc" "ghci" "gimp" "ginsh" "git" "grc" 
            "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "iftop" "install" 
            "ionice" "ip" "irb" "ispell" "jjs" "joe" "join" "journalctl" "jq" "jrunscript" "jtag" "julia" 
            "knife" "ksh" "ksshell" "ksu" "kubectl" "latex" "latexmk" "ld.so" "ldconfig" "less" "lftp" 
            "links" "ln" "loginctl" "logsave" "look" "ltrace" "lua" "lualatex" "luatex" "lwp-download" 
            "lwp-request" "mail" "make" "man" "mawk" "minicom" "more" "mosquitto" "mount" "msfconsole" 
            "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge" "msguniq" "mtr" "multitime" "mv" "mysql" 
            "nano" "nasm" "nawk" "nc" "ncdu" "ncftp" "neofetch" "nft" "nice" "nl" "nm" "nmap" "node" 
            "nohup" "npm" "nroff" "nsenter" "ntpdate" "octave" "od" "openssl" "openvpn" "openvt" "opkg" 
            "pandoc" "paste" "pdb" "pdflatex" "pdftex" "perf" "perl" "perlbug" "pexec" "pg" "php" "pic" 
            "pico" "pidstat" "pip" "pkexec" "pkg" "posh" "pr" "pry" "psftp" "psql" "ptx" "puppet" "pwsh" 
            "python" "rake" "rc" "readelf" "red" "redcarpet" "restic" "rev" "rlwrap" "rpm" "rpmdb" 
            "rpmquery" "rpmverify" "rsync" "ruby" "run-mailcap" "run-parts" "runscript" "rview" "rvim" 
            "sash" "scanmem" "scp" "screen" "script" "scrot" "sed" "service" "setarch" "setfacl" "setlock" 
            "sftp" "sg" "shuf" "slsh" "smbclient" "snap" "socat" "soelim" "softlimit" "sort" "split" 
            "sqlite3" "sqlmap" "ss" "ssh-agent" "ssh-keygen" "ssh-keyscan" "ssh" "sshpass" "start-stop-daemon" 
            "stdbuf" "strace" "strings" "su" "sudo" "sysctl" "systemctl" "systemd-resolve" "tac" "tail" 
            "tar" "task" "taskset" "tasksh" "tbl" "tclsh" "tcpdump" "tdbtool" "tee" "telnet" "terraform" 
            "tex" "tftp" "tic" "time" "timedatectl" "timeout" "tmate" "tmux" "top" "torify" "torsocks" 
            "troff" "ul" "unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" 
            "uuencode" "vagrant" "valgrind" "varnishncsa" "vi" "view" "vigr" "vim" "vimdiff" "vipw" "virsh" 
            "w3m" "wall" "watch" "wc" "wget" "whiptail" "wireshark" "wish" "xargs" "xdg-user-dir" "xdotool" 
            "xelatex" "xetex" "xmodmap" "xmore" "xpad" "xxd" "xz" "yarn" "yash" "zathura" "zip" "zsh" 
            "zsoelim" "zypper"
            # Traditional dangerous commands
            "passwd" "shadow" "usermod" "useradd" "userdel"
        )
        
        for dangerous_cmd in "${dangerous_cmds[@]}"; do
            if [[ "$commands" =~ $dangerous_cmd ]]; then
                return 0
            fi
        done
        return 1
    }

    # Get risk flags for sudoers entry
    get_risk_flags() {
        local permissions="$1"
        local commands="$2"
        local flags=""
        
        # Check for NOPASSWD
        if [[ "$permissions" =~ NOPASSWD ]]; then
            flags+="[NOPASSWD] "
        fi
        
        # Check for ALL=(ALL) ALL grants
        if [[ "$permissions" =~ ALL=\(ALL\) ]] && [[ "$commands" =~ ^ALL$ ]]; then
            flags+="[FULL-ROOT] "
        fi
        
        # Check for wildcards in commands
        if [[ "$commands" =~ \* ]]; then
            flags+="[WILDCARD] "
        fi
        
        # Check for dangerous commands
        if contains_dangerous_commands "$commands"; then
            flags+="[DANGEROUS-CMD] "
        fi
        
        # Check for root user specification
        if [[ "$permissions" =~ ALL=\(root\) ]] || [[ "$permissions" =~ \(root\) ]]; then
            flags+="[ROOT-USER] "
        fi
        
        if [[ -n "$flags" ]]; then
            echo "[HIGH-RISK] ${flags%% }"
        else
            echo ""
        fi
    }

    # Parse sudoers files
    parse_sudoers_files() {
        log "Parsing sudoers configuration files"
        
        local -a sudoers_files=("/etc/sudoers")
        
        # Add files from /etc/sudoers.d/ if directory exists
        if [[ -d /etc/sudoers.d ]]; then
            while IFS= read -r -d '' file; do
                sudoers_files+=("$file")
            done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
        fi
        
        # Process each sudoers file
        for sudoers_file in "${sudoers_files[@]}"; do
            [[ -r "$sudoers_file" ]] || continue
            
            log "Processing $sudoers_file"
            
            while read -r line; do
                # Skip comments, empty lines, and variable assignments
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*[A-Za-z_]+ ]] && continue
                [[ "$line" =~ ^[[:space:]]*Defaults ]] && continue
                [[ "$line" =~ ^[[:space:]]*Cmnd_Alias ]] && continue
                [[ "$line" =~ ^[[:space:]]*User_Alias ]] && continue
                [[ "$line" =~ ^[[:space:]]*Host_Alias ]] && continue
                [[ "$line" =~ ^[[:space:]]*Runas_Alias ]] && continue
                
                # Parse sudoers rule: user/group host=(runas) commands
                # Format: user host=(runas_user:runas_group) commands
                # Simplified parsing for common formats
                if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
                    local entity="${BASH_REMATCH[1]}"
                    local host="${BASH_REMATCH[2]}"
                    local remainder="${BASH_REMATCH[3]}"
                    
                    # Parse the remainder for runas and commands
                    local runas="(root)"
                    local nopasswd=""
                    local commands=""
                    
                    # Check for NOPASSWD
                    if [[ "$remainder" =~ NOPASSWD: ]]; then
                        nopasswd="NOPASSWD:"
                        remainder="${remainder//NOPASSWD:/}"
                    fi
                    
                    # Extract runas if present (format: (user) or (user:group))
                    if [[ "$remainder" == \(* ]]; then
                        # Find closing parenthesis position  
                        local temp="${remainder#(}"  # Remove opening paren
                        local runas_content="${temp%)*}"  # Get content before closing paren  
                        runas="($runas_content)"
                        
                        # Get everything after ") " 
                        commands="${remainder#*) }"
                        # If no space after ), just get everything after )
                        if [[ "$commands" == "$remainder" ]]; then
                            commands="${remainder#*)}"
                        fi
                    else
                        commands="$remainder"
                    fi
                    
                    # Clean up whitespace
                    commands=$(echo "$commands" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
                    
                    # Build permissions string
                    local permissions="$host=$runas"
                    [[ -n "$nopasswd" ]] && permissions="$host=$runas $nopasswd"
                    
                    # Clean up permissions string
                    permissions="${permissions// NOPASSWD:/ NOPASSWD}"
                    
                    # Determine if this is a group (starts with %) or user
                    local entity_type
                    if [[ "$entity" =~ ^% ]]; then
                        entity_type="GROUP"
                        entity="${entity#%}"  # Remove % prefix for display
                    else
                        entity_type="USER"
                    fi
                    
                    # Get risk assessment
                    local risk_flags
                    risk_flags=$(get_risk_flags "$permissions $nopasswd" "$commands")
                    
                    # Categorize the rule
                    if [[ -n "$risk_flags" ]]; then
                        high_risk_rules+=("$entity|$entity_type|$permissions|$commands|$risk_flags")
                    elif [[ "$entity_type" == "GROUP" ]]; then
                        group_privileges+=("$entity|$entity_type|$permissions|$commands|Group privilege")
                    else
                        user_privileges+=("$entity|$entity_type|$permissions|$commands|User privilege")
                    fi
                fi
                
            done < "$sudoers_file"
        done
    }

    # Check for users in administrative groups
    check_admin_groups() {
        log "Checking administrative group memberships"
        
        local -a admin_groups=("wheel" "sudo" "admin")
        
        for group_name in "${admin_groups[@]}"; do
            # Check if group exists
            if getent group "$group_name" >/dev/null 2>&1; then
                local group_members
                group_members=$(getent group "$group_name" | cut -d: -f4)
                
                if [[ -n "$group_members" ]]; then
                    # Process each member
                    IFS=',' read -ra members <<< "$group_members"
                    for member in "${members[@]}"; do
                        member=$(echo "$member" | tr -d ' ')  # Remove spaces
                        [[ -n "$member" ]] || continue
                        
                        # Check if this group grants dangerous privileges
                        local permissions="ALL=(ALL)"
                        local commands="ALL"
                        local risk_flags=""
                        
                        # Most admin groups have NOPASSWD or full privileges
                        if [[ "$group_name" == "wheel" ]]; then
                            risk_flags="[HIGH-RISK] [FULL-ROOT] Admin group"
                        else
                            risk_flags="[HIGH-RISK] [ROOT-ACCESS] Admin group"
                        fi
                        
                        # Add to high-risk since admin group membership is inherently high-risk
                        high_risk_rules+=("$member|USER|$permissions (via $group_name)|$commands|$risk_flags")
                    done
                fi
            fi
        done
    }

    # Function to print section header
    print_header() {
        local title="$1"
        
        echo
        echo "=== $title ==="
        printf "%-${ENTITY_WIDTH}s %-${TYPE_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${COMMANDS_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "ENTITY" "TYPE" "PERMISSIONS" "COMMANDS" "FLAGS"
        printf "%-${ENTITY_WIDTH}s %-${TYPE_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${COMMANDS_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "$(printf '%*s' 6 | tr ' ' '-')" \
            "$(printf '%*s' 4 | tr ' ' '-')" \
            "$(printf '%*s' 11 | tr ' ' '-')" \
            "$(printf '%*s' 8 | tr ' ' '-')" \
            "$(printf '%*s' 5 | tr ' ' '-')"
    }

    # Function to print sudoers rules from array
    print_sudoers_rules() {
        local -n rules_array=$1
        
        for rule_entry in "${rules_array[@]}"; do
            IFS='|' read -r entity entity_type permissions commands flags <<< "$rule_entry"
            printf "%-${ENTITY_WIDTH}s %-${TYPE_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${COMMANDS_WIDTH}s %-${FLAGS_WIDTH}s\n" \
                "$entity" \
                "$entity_type" \
                "${permissions:0:$((PERMISSIONS_WIDTH-1))}" \
                "${commands:0:$((COMMANDS_WIDTH-1))}" \
                "$flags"
        done
    }

    # Function to sort sudoers rules by entity name
    sort_sudoers_rules() {
        local -n rules_array=$1
        local temp_file=$(mktemp)
        
        # Create sortable entries
        for rule_entry in "${rules_array[@]}"; do
            IFS='|' read -r entity rest <<< "$rule_entry"
            echo "${entity}|${rule_entry}" >> "$temp_file"
        done
        
        # Sort by entity name
        rules_array=()
        while IFS='|' read -r entity original_entry; do
            rules_array+=("$original_entry")
        done < <(sort -t'|' -k1,1 "$temp_file")
        
        rm "$temp_file"
    }

    # Remove duplicate entries (can happen when parsing both sudoers and group memberships)
    remove_duplicates() {
        local -n rules_array=$1
        local -A seen_entries
        local -a unique_rules
        
        for rule_entry in "${rules_array[@]}"; do
            IFS='|' read -r entity entity_type permissions commands flags <<< "$rule_entry"
            local key="$entity|$entity_type|$permissions"
            
            if [[ -z "${seen_entries[$key]:-}" ]]; then
                seen_entries["$key"]=1
                unique_rules+=("$rule_entry")
            fi
        done
        
        rules_array=("${unique_rules[@]}")
    }

    # Main enumeration function
    enumerate_sudoers() {
        echo "Sudoers Enumeration - Security Assessment"
        echo "========================================="
        
        # Check if we can read sudoers files
        if [[ ! -r /etc/sudoers ]]; then
            echo "Warning: Cannot read /etc/sudoers - run as root for complete analysis"
        fi
        
        parse_sudoers_files
        check_admin_groups
        
        # Remove duplicates and sort arrays
        remove_duplicates high_risk_rules
        remove_duplicates group_privileges
        remove_duplicates user_privileges
        
        sort_sudoers_rules high_risk_rules
        sort_sudoers_rules group_privileges
        sort_sudoers_rules user_privileges
        
        # Print High-Risk Sudo Rules section
        print_header "High-Risk Sudo Rules"
        if [[ ${#high_risk_rules[@]} -eq 0 ]]; then
            echo "No high-risk sudo rules found."
        else
            print_sudoers_rules high_risk_rules
        fi
        
        # Print Group-Based Privileges section  
        print_header "Group-Based Privileges"
        if [[ ${#group_privileges[@]} -eq 0 ]]; then
            echo "No group-based privileges found."
        else
            print_sudoers_rules group_privileges
        fi
        
        # Print Individual User Privileges section
        print_header "Individual User Privileges"
        if [[ ${#user_privileges[@]} -eq 0 ]]; then
            echo "No individual user privileges found."
        else
            print_sudoers_rules user_privileges
        fi
        
        echo
        echo "Summary:"
        echo "  High-risk rules: ${#high_risk_rules[@]}"
        echo "  Group privileges: ${#group_privileges[@]}"
        echo "  User privileges: ${#user_privileges[@]}"
        
        log "Sudoers enumeration completed - High-risk: ${#high_risk_rules[@]}, Group: ${#group_privileges[@]}, User: ${#user_privileges[@]}"
    }

    #enumerate the sudoers
    enumerate_sudoers
}

get_services(){

    # Arrays to store services by category
    declare -a active_services
    declare -a inactive_services  
    declare -a malformed_services


    # Read systemctl output and categorize services
    while read -r unit load active sub description; do
        # Skip empty lines
        [[ -z "$unit" ]] && continue
        
        # Handle malformed services with ● character (different field order)
        if [[ "$unit" == *"●"* ]]; then
            # For ● entries: ● service.name not-found inactive dead service.name
            service_name=${load%.service}  # load field contains the actual service name
            load_state="$active"           # active field contains the load state
            active_state="$sub"            # sub field contains the active state
            malformed_services+=("$service_name|$active_state|$load_state")
        else
            # Normal services: service.name loaded active sub description
            service_name=${unit%.service}
            
            if [[ "$load" == "not-found" ]]; then
                # Malformed services without ● character
                malformed_services+=("$service_name|$active|$load")
            elif [[ "$active" == "active" ]]; then
                # Active services
                active_services+=("$service_name|$active|$sub")
            else
                # Inactive services (loaded but not active)
                inactive_services+=("$service_name|$active|$sub")
            fi
        fi
    done < <(systemctl list-units --type=service --no-pager --no-legend --all)

    # Function to print section header
    print_header() {
        local title="$1"
        local col3_name="$2"
        
        echo
        echo "=== $title ==="
        printf "%-50s %-10s %-15s\n" "SERVICE" "STATUS" "$col3_name"
        printf "%-50s %-10s %-15s\n" "$(printf '%*s' 50 | tr ' ' '-')" "$(printf '%*s' 10 | tr ' ' '-')" "$(printf '%*s' 15 | tr ' ' '-')"
    }

    # Function to get state priority for sorting (lower number = higher priority)
    get_state_priority() {
        local state="$1"
        case "$state" in
            "degraded")         echo "1" ;;
            "failed")           echo "2" ;;
            "error")            echo "3" ;;
            "activating")       echo "4" ;;
            "deactivating")     echo "5" ;;
            "reloading")        echo "6" ;;
            "running")          echo "7" ;;
            "exited")           echo "8" ;;
            *)                  echo "9" ;;  # Any other states
        esac
    }

    # Function to sort active services by state priority, then by name
    sort_active_services() {
        local -n services_array=$1
        local temp_file=$(mktemp)
        
        # Create sortable entries with priority prefix
        for service_entry in "${services_array[@]}"; do
            IFS='|' read -r name status state <<< "$service_entry"
            priority=$(get_state_priority "$state")
            echo "${priority}|${name}|${service_entry}" >> "$temp_file"
        done
        
        # Sort by priority then by name, then extract original entries
        services_array=()
        while IFS='|' read -r priority name original_entry; do
            services_array+=("$original_entry")
        done < <(sort -t'|' -k1,1n -k2,2 "$temp_file")
        
        rm "$temp_file"
    }

    # Function to sort services alphabetically by name
    sort_services_alphabetically() {
        local -n services_array=$1
        local temp_file=$(mktemp)
        
        # Create sortable entries
        for service_entry in "${services_array[@]}"; do
            IFS='|' read -r name status state <<< "$service_entry"
            echo "${name}|${service_entry}" >> "$temp_file"
        done
        
        # Sort by name, then extract original entries
        services_array=()
        while IFS='|' read -r name original_entry; do
            services_array+=("$original_entry")
        done < <(sort -t'|' -k1,1 "$temp_file")
        
        rm "$temp_file"
    }

    # Function to print services from array
    print_services() {
        local -n services_array=$1
        
        for service_entry in "${services_array[@]}"; do
            IFS='|' read -r name status state <<< "$service_entry"
            printf "%-50s %-10s %-15s\n" "$name" "$status" "$state"
        done
    }

    # Wrapper function to generate the full report
    generate_report() {
        # Print Active Services section
        print_header "Active Services" "STATE"
        if [[ ${#active_services[@]} -eq 0 ]]; then
            echo "No active services found."
        else
            sort_active_services active_services
            print_services active_services
        fi

        # Print Inactive Services section  
        print_header "Inactive Services" "STATE"
        if [[ ${#inactive_services[@]} -eq 0 ]]; then
            echo "No inactive services found."
        else
            sort_services_alphabetically inactive_services
            print_services inactive_services
        fi

        # Print Malformed Services section
        print_header "Malformed Services" "LOAD-STATE"
        if [[ ${#malformed_services[@]} -eq 0 ]]; then
            echo "No malformed services found."
        else
            sort_services_alphabetically malformed_services
            print_services malformed_services
        fi

        echo
        echo "Summary:"
        echo "  Active services: ${#active_services[@]}"
        echo "  Inactive services: ${#inactive_services[@]}"
        echo "  Malformed services: ${#malformed_services[@]}"
    }

    #Generate the report
    generate_report
    log "Service enumeration completed."

}

get_privesc(){

    # Column width configuration
    local BINARY_WIDTH=35
    local OWNER_WIDTH=10
    local PERMISSIONS_WIDTH=12
    local CAPABILITIES_WIDTH=15
    local FLAGS_WIDTH=30

    # Arrays to store findings by category
    declare -a dangerous_suid
    declare -a standard_suid
    declare -a capabilities_binaries


    # Check if binary is in a standard location
    is_standard_location() {
        local binary_path="$1"
        local -a standard_paths=(
            "/usr/bin/" "/bin/" "/usr/sbin/" "/sbin/"
            "/usr/libexec/" "/usr/lib/" "/lib/"
            "/usr/local/bin/" "/usr/local/sbin/"
        )
        
        for std_path in "${standard_paths[@]}"; do
            if [[ "$binary_path" == ${std_path}* ]]; then
                return 0
            fi
        done
        return 1
    }

    # Check if SUID binary is expected/standard
    is_standard_suid() {
        local binary_name="$1"
        local binary_path="$2"
        
        # List of commonly expected SUID binaries
        local -a standard_suid_binaries=(
            "su" "sudo" "passwd" "chsh" "chfn" "newgrp" "gpasswd"
            "mount" "umount" "ping" "ping6" "traceroute" "traceroute6"
            "fusermount" "fusermount3" "pkexec" "polkit-agent-helper-1"
            "ssh-keysign" "unix_chkpwd" "unix2_chkpwd" "chage"
            "expiry" "write" "wall" "at" "crontab" "batch"
            "pam_timestamp_check" "userhelper" "grub2-set-bootflag"
            "krb5_child" "ldap_child" "proxy_child" "selinux_child"
        )
        
        # Check if binary name is in standard list and in standard location
        for std_binary in "${standard_suid_binaries[@]}"; do
            if [[ "$binary_name" == "$std_binary" ]] && is_standard_location "$binary_path"; then
                return 0
            fi
        done
        
        # Check for partial matches (for binaries with longer names)
        if [[ "$binary_name" == *"polkit-agent-hel"* ]] && is_standard_location "$binary_path"; then
            return 0
        fi
        
        return 1
    }

    # Get risk flags for SUID binary
    get_suid_risk_flags() {
        local binary_path="$1"
        local binary_name="$2"
        local owner="$3"
        local flags=""
        
        # Check for non-root owner
        if [[ "$owner" != "root" ]]; then
            flags+="[NON-ROOT-OWNER] "
        fi
        
        # Check for world-writable directories in path
        local dir_path
        dir_path=$(dirname "$binary_path")
        local dir_perms
        dir_perms=$(stat -c "%A" "$dir_path" 2>/dev/null)
        if [[ "$dir_perms" =~ ......w. ]]; then
            flags+="[WRITABLE-DIR] "
        fi
        
        # Check for unusual locations
        if ! is_standard_location "$binary_path"; then
            flags+="[UNUSUAL-LOCATION] "
        fi
        
        # Check for potentially exploitable binaries (based on GTFOBins SUID category)
        # Source: https://gtfobins.github.io/
        local -a exploitable_binaries=(
            "7z" "aa-exec" "ab" "agetty" "alpine" "ar" "arj" "arp" "as" "ascii-xfr" "ash" "aspell" "atobm" 
            "awk" "base32" "base64" "basenc" "basez" "bash" "bc" "bridge" "busctl" "busybox" "byebug" 
            "bzip2" "cabal" "capsh" "cat" "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "column" 
            "comm" "cp" "cpio" "cpulimit" "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" 
            "date" "dc" "dd" "debugfs" "dialog" "diff" "dig" "distcc" "dmsetup" "docker" "dosbox" "ed" 
            "efax" "elvish" "emacs" "env" "eqn" "espeak" "expect" "file" "find" "fish" "flock" "fmt" 
            "fold" "gawk" "gcore" "gdb" "genie" "genisoimage" "gimp" "ginsh" "grep" "gtester" "gzip" 
            "hd" "head" "hexdump" "highlight" "hping3" "iconv" "install" "ionice" "ip" "ispell" "jjs" 
            "jrunscript" "julia" "ksh" "ksshell" "kubectl" "ld.so" "ldconfig" "less" "lftp" "links" 
            "logsave" "look" "lua" "lualatex" "luatex" "make" "man" "mawk" "minicom" "more" "mosquitto" 
            "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge" "msguniq" "multitime" "mv" "mysql" 
            "nano" "nasm" "nawk" "nc" "ncdu" "ncftp" "nft" "nice" "nl" "nm" "nmap" "node" "nohup" 
            "ntpdate" "octave" "od" "openssl" "openvpn" "pandoc" "paste" "pexec" "pg" "perf" "php" 
            "pic" "pico" "pidstat" "pr" "pry" "psftp" "ptx" "python" "rc" "readelf" "rev" "rlwrap" 
            "rpm" "rpmdb" "rpmquery" "rpmverify" "rsync" "rtorrent" "run-parts" "runscript" "rview" 
            "rvim" "sash" "scanmem" "scp" "sed" "setarch" "setfacl" "setlock" "shuf" "slsh" "soelim" 
            "softlimit" "sort" "sqlite3" "sqlmap" "ss" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass" 
            "start-stop-daemon" "stdbuf" "strace" "strings" "sysctl" "systemctl" "tac" "tail" "tar" 
            "taskset" "tasksh" "tbl" "tclsh" "tee" "terraform" "tftp" "tic" "time" "timeout" "tmate" 
            "troff" "tshark" "ul" "unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives" 
            "uudecode" "uuencode" "vagrant" "varnishncsa" "view" "vigr" "vim" "vimdiff" "vipw" "w3m" 
            "watch" "wc" "wget" "whiptail" "xargs" "xdotool" "xmodmap" "xmore" "xxd" "xz" "yash" "zsh" 
            "zsoelim"
        )
        
        for exploitable in "${exploitable_binaries[@]}"; do
            if [[ "$binary_name" == "$exploitable" ]]; then
                flags+="[GTFOBINS-EXPLOITABLE] "
                break
            fi
        done
        
        # Check for development tools
        if [[ "$binary_name" =~ (gcc|g\+\+|make|cmake|gdb|strace|ltrace) ]]; then
            flags+="[DEV-TOOL] "
        fi
        
        if [[ -n "$flags" ]]; then
            echo "[DANGEROUS] ${flags%% }"
        else
            echo ""
        fi
    }

    # Check if binary is known to be exploitable with capabilities (based on GTFOBins)
    is_gtfobins_capabilities_exploitable() {
        local binary_name="$1"
        local -a capabilities_exploitable=(
            "gdb" "node" "perl" "php" "python" "ruby" "rview" "rvim" "view" "vim" "vimdiff"
        )
        
        for exploitable in "${capabilities_exploitable[@]}"; do
            if [[ "$binary_name" == "$exploitable" ]]; then
                return 0
            fi
        done
        return 1
    }

    # Check if capability is dangerous
    is_dangerous_capability() {
        local capability="$1"
        
        # Very dangerous capabilities (immediate privilege escalation potential)
        local -a critical_caps=(
            "cap_setuid" "cap_setgid" "cap_dac_override" "cap_sys_admin" 
            "cap_sys_ptrace" "cap_sys_module" "cap_setpcap"
        )
        
        # Dangerous capabilities (significant privilege escalation potential)
        local -a dangerous_caps=(
            "cap_dac_read_search" "cap_fowner" "cap_fsetid" "cap_sys_rawio"
            "cap_chown" "cap_kill" "cap_sys_chroot" "cap_net_admin"
        )
        
        # Check for critical capabilities with effective permissions
        for critical_cap in "${critical_caps[@]}"; do
            if [[ "$capability" == *"$critical_cap"*"ep"* ]] || [[ "$capability" == *"$critical_cap"*"e"* ]]; then
                return 0
            fi
        done
        
        # Check for dangerous capabilities with effective permissions
        for dangerous_cap in "${dangerous_caps[@]}"; do
            if [[ "$capability" == *"$dangerous_cap"*"ep"* ]] || [[ "$capability" == *"$dangerous_cap"*"e"* ]]; then
                return 0
            fi
        done
        
        # cap_net_raw with effective is concerning but common for network tools
        if [[ "$capability" == *"cap_net_raw"*"ep"* ]]; then
            return 0
        fi
        
        return 1
    }

    # Get capability risk flags
    get_capability_risk_flags() {
        local capabilities="$1"
        local binary_path="$2"
        local binary_name
        binary_name=$(basename "$binary_path")
        local flags=""
        
        # Check for dangerous capabilities
        if is_dangerous_capability "$capabilities"; then
            flags+="[DANGEROUS-CAP] "
        fi
        
        # Check if binary is known GTFOBins capabilities-exploitable
        if is_gtfobins_capabilities_exploitable "$binary_name"; then
            flags+="[GTFOBINS-EXPLOITABLE] "
        fi
        
        # Check for multiple capabilities
        if [[ $(echo "$capabilities" | grep -o "cap_" | wc -l) -gt 2 ]]; then
            flags+="[MULTIPLE-CAPS] "
        fi
        
        # Check for unusual location
        if ! is_standard_location "$binary_path"; then
            flags+="[UNUSUAL-LOCATION] "
        fi
        
        # Check for world-writable directory
        local dir_path
        dir_path=$(dirname "$binary_path")
        local dir_perms
        dir_perms=$(stat -c "%A" "$dir_path" 2>/dev/null)
        if [[ "$dir_perms" =~ ......w. ]]; then
            flags+="[WRITABLE-DIR] "
        fi
        
        # Check for effective vs permitted capabilities
        if [[ "$capabilities" == *"+ep"* ]]; then
            flags+="[EFFECTIVE-CAPS] "
        fi
        
        # Determine risk level
        if [[ -n "$flags" ]]; then
            echo "[HIGH-RISK] ${flags%% }"
        elif [[ "$capabilities" == *"=p"* ]] && ! is_dangerous_capability "$capabilities"; then
            # Permitted but not effective, and not dangerous - likely normal
            echo "[LOW-RISK]"
        else
            echo "[CAPS-ENABLED]"
        fi
    }

    # Find and categorize SUID binaries
    enumerate_suid_binaries() {
        log "Enumerating SUID binaries"
        
        # Find all SUID binaries
        while read -r suid_binary; do
            [[ -n "$suid_binary" ]] || continue
            
            local binary_name
            binary_name=$(basename "$suid_binary")
            
            # Get file details
            local file_details owner permissions
            file_details=$(ls -la "$suid_binary" 2>/dev/null) || continue
            owner=$(echo "$file_details" | awk '{print $3}')
            permissions=$(echo "$file_details" | awk '{print $1}')
            
            # Get risk assessment
            local risk_flags
            risk_flags=$(get_suid_risk_flags "$suid_binary" "$binary_name" "$owner")
            
            # Categorize the binary
            if [[ -n "$risk_flags" ]]; then
                dangerous_suid+=("$suid_binary|$owner|$permissions|N/A|$risk_flags")
            elif is_standard_suid "$binary_name" "$suid_binary"; then
                standard_suid+=("$suid_binary|$owner|$permissions|N/A|[STANDARD-SUID]")
            else
                # Non-standard but not flagged as dangerous
                dangerous_suid+=("$suid_binary|$owner|$permissions|N/A|[UNUSUAL] Non-standard SUID")
            fi
            
        done < <(find / -perm -4000 -type f 2>/dev/null)
    }

    # Find and categorize capabilities-enabled binaries
    enumerate_capabilities() {
        log "Enumerating capabilities-enabled binaries"
        
        # Check if getcap is available
        if ! command -v getcap >/dev/null 2>&1; then
            log "getcap not found - skipping capabilities enumeration"
            return
        fi
        
        # Find all binaries with capabilities
        while read -r cap_line; do
            [[ -n "$cap_line" ]] || continue
            
            # Parse getcap output: /path/to/binary capabilities
            local binary_path capabilities
            binary_path=$(echo "$cap_line" | awk '{print $1}')
            capabilities=$(echo "$cap_line" | cut -d' ' -f2-)
            
            # Get file details
            local file_details owner permissions
            file_details=$(ls -la "$binary_path" 2>/dev/null) || continue
            owner=$(echo "$file_details" | awk '{print $3}')
            permissions=$(echo "$file_details" | awk '{print $1}')
            
            # Get risk assessment
            local risk_flags
            risk_flags=$(get_capability_risk_flags "$capabilities" "$binary_path")
            
            # Add to capabilities array
            capabilities_binaries+=("$binary_path|$owner|$permissions|$capabilities|$risk_flags")
            
        done < <(getcap -r / 2>/dev/null)
    }

    # Function to print section header
    print_header() {
        local title="$1"
        
        echo
        echo "=== $title ==="
        printf "%-${BINARY_WIDTH}s %-${OWNER_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${CAPABILITIES_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "BINARY" "OWNER" "PERMISSIONS" "CAPABILITIES" "FLAGS"
        printf "%-${BINARY_WIDTH}s %-${OWNER_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${CAPABILITIES_WIDTH}s %-${FLAGS_WIDTH}s\n" \
            "$(printf '%*s' 6 | tr ' ' '-')" \
            "$(printf '%*s' 5 | tr ' ' '-')" \
            "$(printf '%*s' 11 | tr ' ' '-')" \
            "$(printf '%*s' 12 | tr ' ' '-')" \
            "$(printf '%*s' 5 | tr ' ' '-')"
    }

    # Function to print privilege escalation findings from array
    print_privesc_findings() {
        local -n findings_array=$1
        
        for finding_entry in "${findings_array[@]}"; do
            IFS='|' read -r binary owner permissions capabilities flags <<< "$finding_entry"
            printf "%-${BINARY_WIDTH}s %-${OWNER_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${CAPABILITIES_WIDTH}s %-${FLAGS_WIDTH}s\n" \
                "${binary:0:$((BINARY_WIDTH-1))}" \
                "$owner" \
                "$permissions" \
                "${capabilities:0:$((CAPABILITIES_WIDTH-1))}" \
                "$flags"
        done
    }

    # Function to sort findings by binary path
    sort_privesc_findings() {
        local -n findings_array=$1
        local temp_file=$(mktemp)
        
        # Create sortable entries
        for finding_entry in "${findings_array[@]}"; do
            IFS='|' read -r binary rest <<< "$finding_entry"
            echo "${binary}|${finding_entry}" >> "$temp_file"
        done
        
        # Sort by binary path
        findings_array=()
        while IFS='|' read -r binary original_entry; do
            findings_array+=("$original_entry")
        done < <(sort -t'|' -k1,1 "$temp_file")
        
        rm "$temp_file"
    }

    # Main enumeration function
    enumerate_privilege_escalation() {
        echo "Privilege Escalation Enumeration - Security Assessment"
        echo "====================================================="
        
        enumerate_suid_binaries
        enumerate_capabilities
        
        # Sort arrays
        sort_privesc_findings dangerous_suid
        sort_privesc_findings standard_suid
        sort_privesc_findings capabilities_binaries
        
        # Print Dangerous SUID Binaries section
        print_header "Dangerous SUID Binaries"
        if [[ ${#dangerous_suid[@]} -eq 0 ]]; then
            echo "No dangerous SUID binaries found."
        else
            print_privesc_findings dangerous_suid
        fi
        
        # Print Standard SUID Binaries section
        print_header "Standard SUID Binaries"
        if [[ ${#standard_suid[@]} -eq 0 ]]; then
            echo "No standard SUID binaries found."
        else
            print_privesc_findings standard_suid
        fi
        
        # Print Capabilities-Enabled Binaries section
        print_header "Capabilities-Enabled Binaries"
        if [[ ${#capabilities_binaries[@]} -eq 0 ]]; then
            echo "No capabilities-enabled binaries found."
        else
            print_privesc_findings capabilities_binaries
        fi
        
        echo
        echo "Summary:"
        echo "  Dangerous SUID binaries: ${#dangerous_suid[@]}"
        echo "  Standard SUID binaries: ${#standard_suid[@]}"
        echo "  Capabilities-enabled binaries: ${#capabilities_binaries[@]}"
        
        log "Privilege escalation enumeration completed - Dangerous: ${#dangerous_suid[@]}, Standard: ${#standard_suid[@]}, Capabilities: ${#capabilities_binaries[@]}"
    }

    #Execute privalege escalation search logic
    enumerate_privilege_escalation


}


main() {
    echo "Starting Master Security Audit on $HOSTNAME. Logs: $LOG_FILE" 
    log "Starting Master Audit on $HOSTNAME"
    
    {
        # --- HEADER (Screen + Log) ---   
        echo "=================================================================="
        echo "MASTER SECURITY AUDIT REPORT"
        echo "Date: $(date)"
        echo "Hostname: $HOSTNAME"
        echo "=================================================================="
        echo ""
        
        
        # --- 1. GENERAL INVENTORY ---
        get_inventory 
        echo -e "\n\n" 

        # --- 2. CRON JOBS ---
        # Run function, send output to screen AND append to log
        get_cron 
        echo -e "\n\n" 
        
        # --- 3. USERS ---
        get_users
        echo -e "\n\n" 
        
        # --- 4. SUDOERS ---
        get_sudoers 
        echo -e "\n\n" 
        
        # --- 5. SERVICES ---
        echo "Service Enumeration - Security Assessment"
        echo "========================================="
        get_services
        echo -e "\n\n"

        # --- 6. PRIVESC ---
        get_privesc 
        echo -e "\n\n" 
        
        # --- FOOTER ---
        echo "=================================================================="
        echo "AUDIT COMPLETE"
        echo "=================================================================="
    } >> "$LOG_FILE" 2>&1
    
    log "Master Audit completed."
    

    echo "Master Security Audit Completed. Review logs at: $LOG_FILE" 
}

# CALL THE MAIN FUNCTION
main "$@"