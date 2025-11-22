#!/bin/bash

# Cron job enumeration script for security assessment
# Categorizes cron jobs by security risk with suspicious jobs prioritized

set -euo pipefail

# Configuration
LOG_FILE="/var/log/get_cron.log"
ENABLE_LOGGING=${ENABLE_LOGGING:-false}

# Column width configuration
USER_WIDTH=12
SCHEDULE_WIDTH=17
COMMAND_WIDTH=50
FLAGS_WIDTH=25

# Arrays to store cron jobs by category
declare -a suspicious_jobs
declare -a system_jobs
declare -a user_jobs

# Logging function
log() {
    if [[ "$ENABLE_LOGGING" == "true" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    fi
}

# Error handling
error_exit() {
    echo "ERROR: $1" >&2
    log "ERROR: $1"
    exit 1
}

# Check if job is high frequency (runs every minute or more often)
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

# Main function
main() {
    log "Starting cron job enumeration"
    enumerate_cron_jobs
}

# Run main function
main