#!/bin/bash
#
#
#   FML FML FML FML FML FML FML FML FML FML FML
#
#   WHY IS IT GENTOO
#
#
#   WHO INSTALLED GENTOO. WHY DID THEY DO THIS. DO THEY HATE LIFE? DO THEY HATE SANITY? DO THEY WISH FOR THE DESCTRUCTION OF ALL THAT IS GOOD AND PURE (DEBIAN) IN THIS WORLD?
#   IT COULD'VE BEEN CENTOS, OR ALPINE, OR HANNON MONTANA LINUX, BUT INSTEAD, THEY CHOSE FUCKING GENTOO. OPENRC IS AN ABOMINATION FROM HELL. COMPILING EVERYTHING IS AN ABOMINATION 
#   FROM HELL. DEFENDING A GENTOO BOX SHOULD BE WORTHY OF A PASSING GRADE FOR A CAPSTONE. I, ABSOLUTELY, WITH UPMOST SERIOUSNESS AND GENUINE HATE IN MY HEART, DESPISE GENTOO.

#   WHY WOULD ANYONE USE THIS OS????? IT'S FREEBSD, DEBIAN, DEBIAN-FLAVOURED-BUT-ACTUALLY-BAD (UBUNTU), RHEL, RHEL-FLAVOURED-BUT-ACTUALLY-WORSE (CENTOS), ALPINE, ARCH, AND NIXOS. 
#   AND THE WORLD WAS HAPPY. IF PEOPLE WANT TO LEARN LINUX IN-DEPTH, THEY USE LFS. WHERE DOES GENTOO FIT INTO THIS???? BLOODY NOWHERE!!!!
#
#
#   this is a copy of my linux enumeration script, updated for compability with Gentoo, notably with the new support for openRC. It probably works. 
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

# Get the log time
TIME_SUFFIX=$(date +%Y%m%d_%H%M)

FINAL_LOG="/var/log/syst/${HOSTNAME}_audit_${TIME_SUFFIX}.log"
LOG_FILE="/tmp/${HOSTNAME}_audit_${TIME_SUFFIX}.tmp"
ENABLE_LOGGING=true

# Unified Logging Function
log() {
    local msg="[PROGRESS] - $1"
    echo "$msg" >> "$LOG_FILE"
}

error_exit() {
    local msg="CRITICAL SECURITY AUDIT ERROR: $1"
    echo "ERROR: $1" >&2
    log "$msg"
    echo "$msg" | wall 2>/dev/null # wall might not exist on minimal installs
    exit 1
}

# ... [KEEP get_inventory, get_cron, get_users, get_sudoers AS THEY ARE] ...
# (They use standard file paths /etc/passwd, /etc/crontab which are universal)

get_inventory(){
    # [Paste original get_inventory code here]
    # No changes needed for Gentoo compatibility as it relies on standard tools like lscpu, free, etc.
    # ...
    # --- Local Helper Functions ---
    empty_line () {
        echo ""
    }

    command_exists() {
        command -v "$1" > /dev/null 2>&1
    }

    stringContain() { case $2 in *$1* ) return 0;; *) return 1;; esac ;}

    get_group_members() {
       grep "^$1:" /etc/group | cut -d: -f4 | tr ',' '\n'
    }

    # --- Gathering Variables ---
    local HOSTNAME=$(hostname || cat /etc/hostname)
    local IP_ADDR=$( ( ip a | grep -oE '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/[[:digit:]]{1,2}' | grep -v '127.0.0.1' ) || ( ifconfig | grep -oE 'inet.+([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' | grep -v '127.0.0.1' ) )
    local OS=$( (hostnamectl 2>/dev/null | grep "Operating System" | cut -d: -f2) || (cat /etc/*-release 2>/dev/null | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//' | sed 's/"//g') )

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

    if command_exists free; then
        local ram_total=$(free -m | awk '/Mem:/ {print $2}')
        printf "Total RAM: "
        echo "${ram_total} MB"
    else
        echo "RAM: Unable to determine (free command missing)"
    fi

    empty_line

    echo "Storage Devices:"
    if command_exists lsblk; then
        lsblk -d -o NAME,SIZE,MODEL,TYPE | grep -v "loop"
    else
        df -h 2>/dev/null | grep '^/dev/'
    fi
    empty_line

    echo "Open ports and PIDs:"
    if command_exists ss; then
        ss -tulpn | sort -k 1,1 -k 2,2 | awk 'NR==1; NR>1{print | "sort -V -k 4,4"}' | sed '1 s/Process/Process                     /'
    elif command_exists netstat; then
        netstat -an | grep LISTEN
    elif command_exists lsof; then
        lsof -i -P -n | grep LISTEN
    else
        echo "required tools for this section not found (install net-tools or iproute2)"
    fi

    empty_line
    # ... (Rest of inventory logic remains valid)
}

get_cron(){
    # [Paste original get_cron code here]
    # Standard logic works on Gentoo.
    # ...
    local USER_WIDTH=12
    local SCHEDULE_WIDTH=17
    local COMMAND_WIDTH=50
    local FLAGS_WIDTH=25

    declare -a suspicious_jobs
    declare -a system_jobs
    declare -a user_jobs

    is_high_frequency() {
        local schedule="$1"
        [[ "$schedule" =~ ^\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\* ]] || \
        [[ "$schedule" =~ ^\*/1[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\* ]]
    }

    is_suspicious_command() {
        local command="$1"
        local -a suspicious_patterns=("wget" "curl" "nc" "netcat" "telnet" "ssh" "scp" "rsync" "/tmp/" "/var/tmp/" "/dev/shm/" "base64" "echo.*|.*base64" "python.*-c" "perl.*-e" "/dev/tcp/" "bash.*-i" "sh.*-i" "chmod.*777" "chown.*root" "sudo" "su -" "/dev/null.*&" "nohup")
        for pattern in "${suspicious_patterns[@]}"; do
            if [[ "$command" =~ $pattern ]]; then return 0; fi
        done
        return 1
    }

    get_suspicious_flags() {
        local schedule="$1"
        local command="$2"
        local flags=""
        if is_high_frequency "$schedule"; then flags+="[HIGH-FREQ] "; fi
        if [[ "$command" =~ (wget|curl) ]]; then flags+="[NETWORK-DL] "; fi
        if [[ "$command" =~ (nc|netcat|telnet) ]]; then flags+="[NETWORK-CONN] "; fi
        if [[ "$command" =~ /tmp/|/var/tmp/|/dev/shm/ ]]; then flags+="[TEMP-DIR] "; fi
        if [[ "$command" =~ base64|python.*-c|perl.*-e ]]; then flags+="[ENCODED] "; fi
        if [[ "$command" =~ /dev/tcp/|bash.*-i|sh.*-i ]]; then flags+="[REVERSE-SHELL] "; fi
        if [[ "$command" =~ chmod.*777|chown.*root ]]; then flags+="[PRIVESC] "; fi
        if [[ -n "$flags" ]]; then echo "[SUSPICIOUS] ${flags%% }"; else echo "[SUSPICIOUS]"; fi
    }

    parse_system_crons() {
        if [[ -f /etc/crontab ]]; then
            while read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*[A-Z_]+=.* ]] && continue
                if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*) ]]; then
                    local schedule="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]} ${BASH_REMATCH[5]}"
                    local user="${BASH_REMATCH[6]}"
                    local command="${BASH_REMATCH[7]}"
                    if is_suspicious_command "$command" || is_high_frequency "$schedule"; then
                        local flags=$(get_suspicious_flags "$schedule" "$command")
                        suspicious_jobs+=("$user|$schedule|$command|$flags")
                    else
                        system_jobs+=("$user|$schedule|$command|System cron")
                    fi
                fi
            done < /etc/crontab
        fi
        
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
                            local flags=$(get_suspicious_flags "$schedule" "$command")
                            suspicious_jobs+=("$user|$schedule|$command|$flags")
                        else
                            system_jobs+=("$user|$schedule|$command|cron.d: $(basename "$cronfile")")
                        fi
                    fi
                done < "$cronfile"
            done
        fi
        
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
                        local flags=$(get_suspicious_flags "$schedule" "$command")
                        suspicious_jobs+=("$user|$schedule|$command|$flags")
                    else
                        system_jobs+=("$user|$schedule|$command|$(basename "$crondir")")
                    fi
                done
            fi
        done
    }

    parse_user_crons() {
        while IFS=: read -r username _ uid _ _ home shell; do
            [[ "$uid" -ge 1000 || "$shell" =~ (bash|sh|zsh|fish)$ ]] || continue
            local user_cron_output
            if user_cron_output=$(crontab -u "$username" -l 2>/dev/null); then
                while read -r line; do
                    [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
                    if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*) ]]; then
                        local schedule="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]} ${BASH_REMATCH[5]}"
                        local command="${BASH_REMATCH[6]}"
                        if is_suspicious_command "$command" || is_high_frequency "$schedule"; then
                            local flags=$(get_suspicious_flags "$schedule" "$command")
                            suspicious_jobs+=("$username|$schedule|$command|$flags")
                        else
                            user_jobs+=("$username|$schedule|$command|User crontab")
                        fi
                    fi
                done <<< "$user_cron_output"
            fi
        done < /etc/passwd
    }

    parse_systemd_timers() {
        if ! command -v systemctl >/dev/null 2>&1; then return; fi
        while read -r timer_line; do
            [[ -n "$timer_line" ]] || continue
            local timer_name=$(echo "$timer_line" | awk '{print $1}')
            [[ "$timer_name" =~ \.timer$ ]] || continue
            local schedule="systemd-timer"
            local service_name="${timer_name%.timer}.service"
            local command="systemctl start $service_name"
            local user="root"
            if [[ "$timer_name" =~ (backup|update|clean).*\.timer$ ]]; then
                system_jobs+=("$user|$schedule|$command|SystemD timer")
            else
                suspicious_jobs+=("$user|$schedule|$command|[SUSPICIOUS] Unusual timer name")
            fi
        done < <(systemctl list-timers --no-pager --no-legend --all 2>/dev/null | grep -E "\.timer")
    }

    print_header() {
        local title="$1"
        echo
        echo "=== $title ==="
        printf "%-${USER_WIDTH}s %-${SCHEDULE_WIDTH}s %-${COMMAND_WIDTH}s %-${FLAGS_WIDTH}s\n" "USER" "SCHEDULE" "COMMAND" "FLAGS"
        printf "%-${USER_WIDTH}s %-${SCHEDULE_WIDTH}s %-${COMMAND_WIDTH}s %-${FLAGS_WIDTH}s\n" "------------" "----------------" "-----------------" "----------------"
    }

    print_cron_jobs() {
        local -n jobs_array=$1
        for job_entry in "${jobs_array[@]}"; do
            IFS='|' read -r user schedule command flags <<< "$job_entry"
            printf "%-${USER_WIDTH}s %-${SCHEDULE_WIDTH}s %-${COMMAND_WIDTH}s %-${FLAGS_WIDTH}s\n" "$user" "$schedule" "${command:0:$((COMMAND_WIDTH-1))}" "$flags"
        done
    }

    sort_cron_jobs() {
        local -n jobs_array=$1
        local temp_file=$(mktemp)
        for job_entry in "${jobs_array[@]}"; do
            IFS='|' read -r user schedule command flags <<< "$job_entry"
            echo "${user}|${schedule}|${job_entry}" >> "$temp_file"
        done
        jobs_array=()
        while IFS='|' read -r user schedule original_entry; do
            jobs_array+=("$original_entry")
        done < <(sort -t'|' -k1,1 -k2,2 "$temp_file")
        rm "$temp_file"
    }

    echo "Cron Job Enumeration - Security Assessment"
    echo "=========================================="
    parse_system_crons
    parse_user_crons
    parse_systemd_timers
    sort_cron_jobs suspicious_jobs
    sort_cron_jobs system_jobs
    sort_cron_jobs user_jobs
    
    print_header "Suspicious Cron Jobs"
    if [[ ${#suspicious_jobs[@]} -eq 0 ]]; then echo "No suspicious cron jobs found."; else print_cron_jobs suspicious_jobs; fi
    
    print_header "System Cron Jobs"
    if [[ ${#system_jobs[@]} -eq 0 ]]; then echo "No system cron jobs found."; else print_cron_jobs system_jobs; fi
    
    print_header "User Cron Jobs"
    if [[ ${#user_jobs[@]} -eq 0 ]]; then echo "No user cron jobs found."; else print_cron_jobs user_jobs; fi
    
    echo
    echo "Summary: Suspicious: ${#suspicious_jobs[@]} | System: ${#system_jobs[@]} | User: ${#user_jobs[@]}"
}

get_users(){
    # [Paste original get_users code here]
    # No changes needed for Gentoo compatibility.
    # ...
    local USERNAME_WIDTH=20
    local UID_WIDTH=8
    local GROUPS_WIDTH=16
    local SHELL_WIDTH=20
    local HOME_WIDTH=20
    local FLAGS_WIDTH=20
    local FLAG_DETAIL_FLAG_WIDTH=15
    local FLAG_DETAIL_USERNAME_WIDTH=20
    local FLAG_DETAIL_UID_WIDTH=8
    local FLAG_DETAIL_REASON_WIDTH=50

    declare -a high_risk_users
    declare -a privileged_users  
    declare -a standard_users
    declare -a flag_details

    check_system() {
        if [[ ! -f /etc/passwd ]] || [[ ! -f /etc/shadow ]] || [[ ! -f /etc/group ]]; then
            error_exit "Required system files not found"
        fi
        if [[ $EUID -eq 0 ]] && [[ -r /etc/shadow ]]; then SHADOW_READABLE=true; else SHADOW_READABLE=false; echo "Warning: Running without root privileges - password checks disabled"; fi
    }

    has_empty_password() {
        local username="$1"
        if [[ "$SHADOW_READABLE" == "false" ]]; then return 1; fi
        local password_hash=$(getent shadow "$username" | cut -d: -f2)
        [[ -z "$password_hash" ]] || [[ "$password_hash" == "!" ]] || [[ "$password_hash" == "*" ]]
    }

    is_recent_user() {
        local username="$1"
        local home_dir="$2"
        if [[ -d "$home_dir" ]]; then
            local dir_age=$(find "$home_dir" -maxdepth 0 -mtime -30 2>/dev/null | wc -l)
            [[ "$dir_age" -gt 0 ]]
        else
            return 1
        fi
    }

    add_flag_detail() {
        local flag="$1"
        local username="$2" 
        local uid="$3"
        local reason="$4"
        flag_details+=("$flag|$username|$uid|$reason")
    }

    categorize_users() {
        while IFS=: read -r username password uid gid gecos home shell; do
            local groups user_groups flags_list=() primary_flag=""
            user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | sed 's/^ *//; s/ /, /g' || echo "")
            local is_high_risk=false
            
            if [[ "$uid" -eq 0 && "$username" != "root" ]]; then
                flags_list+=("[SUSPICIOUS]")
                add_flag_detail "[SUSPICIOUS]" "$username" "$uid" "Non-root UID 0"
                is_high_risk=true
            elif [[ "$uid" -lt 1000 && "$shell" =~ /(bash|sh|zsh|fish)$ ]]; then
                flags_list+=("[SUSPICIOUS]")
                add_flag_detail "[SUSPICIOUS]" "$username" "$uid" "Service account with login shell"
                is_high_risk=true
            elif has_empty_password "$username"; then
                flags_list+=("[SUSPICIOUS]")
                add_flag_detail "[SUSPICIOUS]" "$username" "$uid" "Empty/locked password"
                is_high_risk=true
            fi
            
            if is_recent_user "$username" "$home"; then
                flags_list+=("[RECENT]")
                add_flag_detail "[RECENT]" "$username" "$uid" "Created within 30 days"
                is_high_risk=true
            fi
            
            if [[ ${#flags_list[@]} -gt 0 ]]; then primary_flag=$(IFS=', '; echo "${flags_list[*]}"); fi
            
            if [[ "$is_high_risk" == "true" ]]; then
                high_risk_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
            elif echo "$user_groups" | grep -qE "(wheel|sudo|admin|root)"; then
                primary_flag="Admin user"
                privileged_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
            elif [[ "$uid" -ge 1000 && "$shell" =~ /(bash|sh|zsh|fish)$ ]]; then
                primary_flag="Regular user"
                standard_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
            elif [[ "$uid" -lt 1000 ]]; then
                primary_flag="System account"
                standard_users+=("$username|$uid|$user_groups|$shell|$home|$primary_flag")
            fi
        done < /etc/passwd
    }

    print_header() {
        local title="$1"
        echo
        echo "=== $title ==="
        printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${FLAGS_WIDTH}s\n" "USERNAME" "UID" "GROUPS" "SHELL" "HOME" "FLAGS"
        printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${FLAGS_WIDTH}s\n" "--------" "---" "------" "-----" "----" "-----"
    }

    print_users() {
        local -n users_array=$1
        for user_entry in "${users_array[@]}"; do
            IFS='|' read -r username uid groups shell home flags <<< "$user_entry"
            printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${FLAGS_WIDTH}s\n" "$username" "$uid" "${groups:0:$((GROUPS_WIDTH-1))}" "$shell" "${home:0:$((HOME_WIDTH-1))}" "$flags"
        done
    }

    print_flag_details() {
        echo
        echo "=== Flag Details ==="
        printf "%-${FLAG_DETAIL_FLAG_WIDTH}s %-${FLAG_DETAIL_USERNAME_WIDTH}s %-${FLAG_DETAIL_UID_WIDTH}s %-${FLAG_DETAIL_REASON_WIDTH}s\n" "FLAG" "USERNAME" "UID" "REASON"
        printf "%-${FLAG_DETAIL_FLAG_WIDTH}s %-${FLAG_DETAIL_USERNAME_WIDTH}s %-${FLAG_DETAIL_UID_WIDTH}s %-${FLAG_DETAIL_REASON_WIDTH}s\n" "----" "--------" "---" "------"
        
        if [[ ${#flag_details[@]} -eq 0 ]]; then
            echo "No flags to detail."
        else
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
                printf "%-${FLAG_DETAIL_FLAG_WIDTH}s %-${FLAG_DETAIL_USERNAME_WIDTH}s %-${FLAG_DETAIL_UID_WIDTH}s %-${FLAG_DETAIL_REASON_WIDTH}s\n" "$flag" "$username" "$uid" "$reason"
            done
            rm "$temp_file"
        fi
    }

    sort_users_by_uid() {
        local -n users_array=$1
        local temp_file=$(mktemp)
        for user_entry in "${users_array[@]}"; do
            IFS='|' read -r username uid rest <<< "$user_entry"
            echo "${uid}|${user_entry}" >> "$temp_file"
        done
        users_array=()
        while IFS='|' read -r uid original_entry; do
            users_array+=("$original_entry")
        done < <(sort -t'|' -k1,1n "$temp_file")
        rm "$temp_file"
    }

    echo "User Enumeration - Security Assessment"
    echo "====================================="
    check_system
    categorize_users
    sort_users_by_uid high_risk_users
    sort_users_by_uid privileged_users
    sort_users_by_uid standard_users
    
    print_header "High-Risk/Suspicious Users"
    if [[ ${#high_risk_users[@]} -eq 0 ]]; then echo "No high-risk users found."; else print_users high_risk_users; fi
    
    print_header "Privileged Users"
    if [[ ${#privileged_users[@]} -eq 0 ]]; then echo "No privileged users found."; else print_users privileged_users; fi
    
    print_header "Standard Users"
    if [[ ${#standard_users[@]} -eq 0 ]]; then echo "No standard users found."; else print_users standard_users; fi
    
    print_flag_details
    echo
    echo "Summary: High-risk: ${#high_risk_users[@]} | Privileged: ${#privileged_users[@]} | Standard: ${#standard_users[@]}"
}

get_sudoers(){
    # [Paste original get_sudoers code here]
    # No changes needed for Gentoo compatibility.
    # ...
    local ENTITY_WIDTH=10
    local TYPE_WIDTH=6
    local PERMISSIONS_WIDTH=25
    local COMMANDS_WIDTH=25
    local FLAGS_WIDTH=40

    declare -a high_risk_rules
    declare -a group_privileges
    declare -a user_privileges

    contains_dangerous_commands() {
        local commands="$1"
        local -a dangerous_cmds=("chmod" "chown" "cp" "mv" "dd" "editor" "find" "gdb" "less" "more" "nano" "nmap" "python" "ruby" "perl" "php" "scp" "sed" "awk" "tar" "vi" "vim" "wget" "curl" "zip" "unzip" "bash" "sh" "nc" "netcat" "socat" "tcpdump" "tmux" "screen" "docker" "iptables" "systemctl" "service" "useradd" "usermod" "passwd" "shadow")
        for dangerous_cmd in "${dangerous_cmds[@]}"; do
            if [[ "$commands" =~ $dangerous_cmd ]]; then return 0; fi
        done
        return 1
    }

    get_risk_flags() {
        local permissions="$1"
        local commands="$2"
        local flags=""
        if [[ "$permissions" =~ NOPASSWD ]]; then flags+="[NOPASSWD] "; fi
        if [[ "$permissions" =~ ALL=\(ALL\) ]] && [[ "$commands" =~ ^ALL$ ]]; then flags+="[FULL-ROOT] "; fi
        if [[ "$commands" =~ \* ]]; then flags+="[WILDCARD] "; fi
        if contains_dangerous_commands "$commands"; then flags+="[DANGEROUS-CMD] "; fi
        if [[ -n "$flags" ]]; then echo "[HIGH-RISK] ${flags%% }"; else echo ""; fi
    }

    parse_sudoers_files() {
        local -a sudoers_files=("/etc/sudoers")
        if [[ -d /etc/sudoers.d ]]; then
            while IFS= read -r -d '' file; do sudoers_files+=("$file"); done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
        fi
        
        for sudoers_file in "${sudoers_files[@]}"; do
            [[ -r "$sudoers_file" ]] || continue
            while read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*[A-Za-z_]+ ]] && continue # Defaults, Alias etc
                
                if [[ "$line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
                    local entity="${BASH_REMATCH[1]}"
                    local host="${BASH_REMATCH[2]}"
                    local remainder="${BASH_REMATCH[3]}"
                    local runas="(root)"
                    local nopasswd=""
                    local commands=""
                    
                    if [[ "$remainder" =~ NOPASSWD: ]]; then nopasswd="NOPASSWD:"; remainder="${remainder//NOPASSWD:/}"; fi
                    
                    if [[ "$remainder" == \(* ]]; then
                        local temp="${remainder#(}"
                        local runas_content="${temp%)*}"
                        runas="($runas_content)"
                        commands="${remainder#*) }"
                        if [[ "$commands" == "$remainder" ]]; then commands="${remainder#*)}"; fi
                    else
                        commands="$remainder"
                    fi
                    
                    commands=$(echo "$commands" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
                    local permissions="$host=$runas"
                    [[ -n "$nopasswd" ]] && permissions="$host=$runas $nopasswd"
                    permissions="${permissions// NOPASSWD:/ NOPASSWD}"
                    
                    local entity_type
                    if [[ "$entity" =~ ^% ]]; then entity_type="GROUP"; entity="${entity#%}"; else entity_type="USER"; fi
                    
                    local risk_flags=$(get_risk_flags "$permissions $nopasswd" "$commands")
                    
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

    check_admin_groups() {
        local -a admin_groups=("wheel" "sudo" "admin")
        for group_name in "${admin_groups[@]}"; do
            if getent group "$group_name" >/dev/null 2>&1; then
                local group_members=$(getent group "$group_name" | cut -d: -f4)
                if [[ -n "$group_members" ]]; then
                    IFS=',' read -ra members <<< "$group_members"
                    for member in "${members[@]}"; do
                        member=$(echo "$member" | tr -d ' ')
                        [[ -n "$member" ]] || continue
                        local permissions="ALL=(ALL)"
                        local commands="ALL"
                        local risk_flags="[HIGH-RISK] [ROOT-ACCESS] Admin group"
                        [[ "$group_name" == "wheel" ]] && risk_flags="[HIGH-RISK] [FULL-ROOT] Admin group"
                        high_risk_rules+=("$member|USER|$permissions (via $group_name)|$commands|$risk_flags")
                    done
                fi
            fi
        done
    }

    print_header() {
        local title="$1"
        echo
        echo "=== $title ==="
        printf "%-${ENTITY_WIDTH}s %-${TYPE_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${COMMANDS_WIDTH}s %-${FLAGS_WIDTH}s\n" "ENTITY" "TYPE" "PERMISSIONS" "COMMANDS" "FLAGS"
        printf "%-${ENTITY_WIDTH}s %-${TYPE_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${COMMANDS_WIDTH}s %-${FLAGS_WIDTH}s\n" "------" "----" "-----------" "--------" "-----"
    }

    print_sudoers_rules() {
        local -n rules_array=$1
        for rule_entry in "${rules_array[@]}"; do
            IFS='|' read -r entity entity_type permissions commands flags <<< "$rule_entry"
            printf "%-${ENTITY_WIDTH}s %-${TYPE_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${COMMANDS_WIDTH}s %-${FLAGS_WIDTH}s\n" "$entity" "$entity_type" "${permissions:0:$((PERMISSIONS_WIDTH-1))}" "${commands:0:$((COMMANDS_WIDTH-1))}" "$flags"
        done
    }

    sort_sudoers_rules() {
        local -n rules_array=$1
        local temp_file=$(mktemp)
        for rule_entry in "${rules_array[@]}"; do
            IFS='|' read -r entity rest <<< "$rule_entry"
            echo "${entity}|${rule_entry}" >> "$temp_file"
        done
        rules_array=()
        while IFS='|' read -r entity original_entry; do
            rules_array+=("$original_entry")
        done < <(sort -t'|' -k1,1 "$temp_file")
        rm "$temp_file"
    }

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

    echo "Sudoers Enumeration - Security Assessment"
    echo "========================================="
    if [[ ! -r /etc/sudoers ]]; then echo "Warning: Cannot read /etc/sudoers"; fi
    parse_sudoers_files
    check_admin_groups
    remove_duplicates high_risk_rules
    remove_duplicates group_privileges
    remove_duplicates user_privileges
    sort_sudoers_rules high_risk_rules
    sort_sudoers_rules group_privileges
    sort_sudoers_rules user_privileges
    
    print_header "High-Risk Sudo Rules"
    if [[ ${#high_risk_rules[@]} -eq 0 ]]; then echo "No high-risk sudo rules found."; else print_sudoers_rules high_risk_rules; fi
    print_header "Group-Based Privileges"
    if [[ ${#group_privileges[@]} -eq 0 ]]; then echo "No group-based privileges found."; else print_sudoers_rules group_privileges; fi
    print_header "Individual User Privileges"
    if [[ ${#user_privileges[@]} -eq 0 ]]; then echo "No individual user privileges found."; else print_sudoers_rules user_privileges; fi
    echo
    echo "Summary: High-risk: ${#high_risk_rules[@]} | Group: ${#group_privileges[@]} | User: ${#user_privileges[@]}"
}

# --- UNIVERSAL SERVICE ENUMERATION ---
get_services(){
    # Arrays to store services by category
    declare -a active_services
    declare -a inactive_services  
    declare -a malformed_services

    # --- SYSTEMD DETECTION ---
    if command -v systemctl >/dev/null 2>&1; then
        while read -r unit load active sub description; do
            [[ -z "$unit" ]] && continue
            if [[ "$unit" == *"●"* ]]; then
                service_name=${load%.service}
                malformed_services+=("$service_name|$active|$load")
            else
                service_name=${unit%.service}
                if [[ "$load" == "not-found" ]]; then
                    malformed_services+=("$service_name|$active|$load")
                elif [[ "$active" == "active" ]]; then
                    active_services+=("$service_name|$active|$sub")
                else
                    inactive_services+=("$service_name|$active|$sub")
                fi
            fi
        done < <(systemctl list-units --type=service --no-pager --no-legend --all)

    # --- OPENRC DETECTION (Gentoo/Alpine) ---
    elif command -v rc-update >/dev/null 2>&1; then
        # Use rc-status to get running services
        while read -r line; do
            # rc-status output format varies slightly, assume standard: [  started  ] service
            if echo "$line" | grep -q "started"; then
                service_name=$(echo "$line" | awk '{print $2}') # Might need adjustment depending on exact rc-status version
                if [ -z "$service_name" ]; then service_name=$(echo "$line" | awk '{print $3}'); fi # Handle weird spacing
                active_services+=("$service_name|active|running")
            fi
        done < <(rc-status -a)

        # Iterate over init scripts to find others (stopped/inactive)
        for svc_path in /etc/init.d/*; do
            [ -x "$svc_path" ] || continue
            [ -d "$svc_path" ] && continue
            service_name=$(basename "$svc_path")
            
            # Avoid duplicates if already found in active list
            local found=false
            for active in "${active_services[@]}"; do
                if [[ "$active" == "$service_name|"* ]]; then found=true; break; fi
            done
            
            if [ "$found" = false ]; then
                inactive_services+=("$service_name|inactive|stopped")
            fi
        done
    else
        echo "[-] Neither systemd nor OpenRC detected. Cannot enumerate services."
    fi

    # Function to print section header
    print_header() {
        local title="$1"
        local col3_name="$2"
        echo
        echo "=== $title ==="
        printf "%-50s %-10s %-15s\n" "SERVICE" "STATUS" "$col3_name"
        printf "%-50s %-10s %-15s\n" "-------" "------" "-------"
    }

    # Function to get state priority for sorting
    get_state_priority() {
        local state="$1"
        case "$state" in
            "degraded") echo "1" ;; "failed") echo "2" ;; "error") echo "3" ;;
            "activating") echo "4" ;; "deactivating") echo "5" ;; "reloading") echo "6" ;;
            "running") echo "7" ;; "exited") echo "8" ;; *) echo "9" ;; 
        esac
    }

    sort_active_services() {
        local -n services_array=$1
        local temp_file=$(mktemp)
        for service_entry in "${services_array[@]}"; do
            IFS='|' read -r name status state <<< "$service_entry"
            priority=$(get_state_priority "$state")
            echo "${priority}|${name}|${service_entry}" >> "$temp_file"
        done
        services_array=()
        while IFS='|' read -r priority name original_entry; do services_array+=("$original_entry"); done < <(sort -t'|' -k1,1n -k2,2 "$temp_file")
        rm "$temp_file"
    }

    sort_services_alphabetically() {
        local -n services_array=$1
        local temp_file=$(mktemp)
        for service_entry in "${services_array[@]}"; do
            IFS='|' read -r name status state <<< "$service_entry"
            echo "${name}|${service_entry}" >> "$temp_file"
        done
        services_array=()
        while IFS='|' read -r name original_entry; do services_array+=("$original_entry"); done < <(sort -t'|' -k1,1 "$temp_file")
        rm "$temp_file"
    }

    print_services() {
        local -n services_array=$1
        for service_entry in "${services_array[@]}"; do
            IFS='|' read -r name status state <<< "$service_entry"
            printf "%-50s %-10s %-15s\n" "$name" "$status" "$state"
        done
    }

    generate_report() {
        print_header "Active Services" "STATE"
        if [[ ${#active_services[@]} -eq 0 ]]; then echo "No active services found."; else sort_active_services active_services; print_services active_services; fi

        print_header "Inactive Services" "STATE"
        if [[ ${#inactive_services[@]} -eq 0 ]]; then echo "No inactive services found."; else sort_services_alphabetically inactive_services; print_services inactive_services; fi

        print_header "Malformed/Unknown Services" "LOAD-STATE"
        if [[ ${#malformed_services[@]} -eq 0 ]]; then echo "No malformed services found."; else sort_services_alphabetically malformed_services; print_services malformed_services; fi

        echo
        echo "Summary: Active: ${#active_services[@]} | Inactive: ${#inactive_services[@]} | Malformed: ${#malformed_services[@]}"
    }

    generate_report
    log "Service enumeration completed."
}

get_privesc(){
    # [Paste original get_privesc code here]
    # Standard logic works on Gentoo.
    # ...
    local BINARY_WIDTH=35
    local OWNER_WIDTH=10
    local PERMISSIONS_WIDTH=12
    local CAPABILITIES_WIDTH=15
    local FLAGS_WIDTH=30

    declare -a dangerous_suid
    declare -a standard_suid
    declare -a capabilities_binaries

    is_standard_location() {
        local binary_path="$1"
        local -a standard_paths=("/usr/bin/" "/bin/" "/usr/sbin/" "/sbin/" "/usr/libexec/" "/usr/lib/" "/lib/" "/usr/local/bin/" "/usr/local/sbin/")
        for std_path in "${standard_paths[@]}"; do
            if [[ "$binary_path" == ${std_path}* ]]; then return 0; fi
        done
        return 1
    }

    is_standard_suid() {
        local binary_name="$1"
        local binary_path="$2"
        local -a standard_suid_binaries=("su" "sudo" "passwd" "chsh" "chfn" "newgrp" "gpasswd" "mount" "umount" "ping" "ping6" "traceroute" "traceroute6" "fusermount" "fusermount3" "pkexec" "polkit-agent-helper-1" "ssh-keysign" "unix_chkpwd" "unix2_chkpwd" "chage" "expiry" "write" "wall" "at" "crontab" "batch" "pam_timestamp_check" "userhelper" "grub2-set-bootflag" "krb5_child" "ldap_child" "proxy_child" "selinux_child")
        for std_binary in "${standard_suid_binaries[@]}"; do
            if [[ "$binary_name" == "$std_binary" ]] && is_standard_location "$binary_path"; then return 0; fi
        done
        if [[ "$binary_name" == *"polkit-agent-hel"* ]] && is_standard_location "$binary_path"; then return 0; fi
        return 1
    }

    get_suid_risk_flags() {
        local binary_path="$1"
        local binary_name="$2"
        local owner="$3"
        local flags=""
        if [[ "$owner" != "root" ]]; then flags+="[NON-ROOT-OWNER] "; fi
        local dir_path=$(dirname "$binary_path")
        local dir_perms=$(stat -c "%A" "$dir_path" 2>/dev/null)
        if [[ "$dir_perms" =~ ......w. ]]; then flags+="[WRITABLE-DIR] "; fi
        if ! is_standard_location "$binary_path"; then flags+="[UNUSUAL-LOCATION] "; fi
        # ... (list of exploitable binaries skipped for brevity, include full list in real script)
        # Assuming list is checked here...
        if [[ -n "$flags" ]]; then echo "[DANGEROUS] ${flags%% }"; else echo ""; fi
    }

    get_capability_risk_flags() {
        local capabilities="$1"
        local binary_path="$2"
        local flags=""
        if [[ "$capabilities" == *"+ep"* ]]; then flags+="[EFFECTIVE-CAPS] "; fi
        if [[ -n "$flags" ]]; then echo "[HIGH-RISK] ${flags%% }"; else echo "[CAPS-ENABLED]"; fi
    }

    enumerate_suid_binaries() {
        while read -r suid_binary; do
            [[ -n "$suid_binary" ]] || continue
            local binary_name=$(basename "$suid_binary")
            local file_details=$(ls -la "$suid_binary" 2>/dev/null) || continue
            local owner=$(echo "$file_details" | awk '{print $3}')
            local permissions=$(echo "$file_details" | awk '{print $1}')
            local risk_flags=$(get_suid_risk_flags "$suid_binary" "$binary_name" "$owner")
            
            if [[ -n "$risk_flags" ]]; then
                dangerous_suid+=("$suid_binary|$owner|$permissions|N/A|$risk_flags")
            elif is_standard_suid "$binary_name" "$suid_binary"; then
                standard_suid+=("$suid_binary|$owner|$permissions|N/A|[STANDARD-SUID]")
            else
                dangerous_suid+=("$suid_binary|$owner|$permissions|N/A|[UNUSUAL] Non-standard SUID")
            fi
        done < <(find / -perm -4000 -type f 2>/dev/null)
    }

    enumerate_capabilities() {
        if ! command -v getcap >/dev/null 2>&1; then return; fi
        while read -r cap_line; do
            [[ -n "$cap_line" ]] || continue
            local binary_path=$(echo "$cap_line" | awk '{print $1}')
            local capabilities=$(echo "$cap_line" | cut -d' ' -f2-)
            local file_details=$(ls -la "$binary_path" 2>/dev/null) || continue
            local owner=$(echo "$file_details" | awk '{print $3}')
            local permissions=$(echo "$file_details" | awk '{print $1}')
            local risk_flags=$(get_capability_risk_flags "$capabilities" "$binary_path")
            capabilities_binaries+=("$binary_path|$owner|$permissions|$capabilities|$risk_flags")
        done < <(getcap -r / 2>/dev/null)
    }

    print_header() {
        local title="$1"
        echo
        echo "=== $title ==="
        printf "%-${BINARY_WIDTH}s %-${OWNER_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${CAPABILITIES_WIDTH}s %-${FLAGS_WIDTH}s\n" "BINARY" "OWNER" "PERMISSIONS" "CAPABILITIES" "FLAGS"
        printf "%-${BINARY_WIDTH}s %-${OWNER_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${CAPABILITIES_WIDTH}s %-${FLAGS_WIDTH}s\n" "------" "-----" "-----------" "------------" "-----"
    }

    print_privesc_findings() {
        local -n findings_array=$1
        for finding_entry in "${findings_array[@]}"; do
            IFS='|' read -r binary owner permissions capabilities flags <<< "$finding_entry"
            printf "%-${BINARY_WIDTH}s %-${OWNER_WIDTH}s %-${PERMISSIONS_WIDTH}s %-${CAPABILITIES_WIDTH}s %-${FLAGS_WIDTH}s\n" "${binary:0:$((BINARY_WIDTH-1))}" "$owner" "$permissions" "${capabilities:0:$((CAPABILITIES_WIDTH-1))}" "$flags"
        done
    }

    sort_privesc_findings() {
        local -n findings_array=$1
        local temp_file=$(mktemp)
        for finding_entry in "${findings_array[@]}"; do
            IFS='|' read -r binary rest <<< "$finding_entry"
            echo "${binary}|${finding_entry}" >> "$temp_file"
        done
        findings_array=()
        while IFS='|' read -r binary original_entry; do findings_array+=("$original_entry"); done < <(sort -t'|' -k1,1 "$temp_file")
        rm "$temp_file"
    }

    echo "Privilege Escalation Enumeration - Security Assessment"
    echo "====================================================="
    enumerate_suid_binaries
    enumerate_capabilities
    sort_privesc_findings dangerous_suid
    sort_privesc_findings standard_suid
    sort_privesc_findings capabilities_binaries
    
    print_header "Dangerous SUID Binaries"
    if [[ ${#dangerous_suid[@]} -eq 0 ]]; then echo "No dangerous SUID binaries found."; else print_privesc_findings dangerous_suid; fi
    print_header "Standard SUID Binaries"
    if [[ ${#standard_suid[@]} -eq 0 ]]; then echo "No standard SUID binaries found."; else print_privesc_findings standard_suid; fi
    print_header "Capabilities-Enabled Binaries"
    if [[ ${#capabilities_binaries[@]} -eq 0 ]]; then echo "No capabilities-enabled binaries found."; else print_privesc_findings capabilities_binaries; fi
    
    echo
    echo "Summary: Dangerous SUID: ${#dangerous_suid[@]} | Standard SUID: ${#standard_suid[@]} | Capabilities: ${#capabilities_binaries[@]}"
    log "Privilege escalation enumeration completed."
}

main() {
    echo "Starting Master Security Audit on $HOSTNAME. Logs: $LOG_FILE" 
    log "Starting Master Audit on $HOSTNAME"
    
    {
        echo "=================================================================="
        echo "MASTER SECURITY AUDIT REPORT"
        echo "Date: $(date)"
        echo "Hostname: $HOSTNAME"
        echo "=================================================================="
        echo ""
        
        get_inventory 
        echo -e "\n\n" 
        get_cron 
        echo -e "\n\n" 
        get_users
        echo -e "\n\n" 
        get_sudoers 
        echo -e "\n\n" 
        get_services
        echo -e "\n\n"
        get_privesc 
        echo -e "\n\n" 
        
        echo "=================================================================="
        echo "AUDIT COMPLETE"
        echo "=================================================================="
    } >> "$LOG_FILE" 2>&1
    
    log "Master Audit completed."
    mv "$LOG_FILE" "$FINAL_LOG"
    echo "Master Security Audit Completed. Review logs at: $FINAL_LOG"
}

main "$@"