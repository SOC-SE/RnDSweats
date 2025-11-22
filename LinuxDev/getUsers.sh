#!/bin/bash

# User enumeration script for security assessment
# Categorizes users by security risk level with suspicious users prioritized

set -euo pipefail

# Configuration
LOG_FILE="/var/log/get_users.log"
ENABLE_LOGGING=${ENABLE_LOGGING:-false}

# Column width configuration
USERNAME_WIDTH=20
UID_WIDTH=8
GROUPS_WIDTH=16
SHELL_WIDTH=20
HOME_WIDTH=20
FLAGS_WIDTH=20

# Flag details column configuration
FLAG_DETAIL_FLAG_WIDTH=15
FLAG_DETAIL_USERNAME_WIDTH=20
FLAG_DETAIL_UID_WIDTH=8
FLAG_DETAIL_REASON_WIDTH=50

# Arrays to store users by category
declare -a high_risk_users
declare -a privileged_users  
declare -a standard_users

# Array to store flag details
declare -a flag_details

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

# Check system compatibility
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
}

# Main function
main() {
    check_system
    enumerate_users
}

# Run main function
main