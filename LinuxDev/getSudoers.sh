#!/bin/bash

# Sudoers enumeration script for security assessment
# Categorizes sudo rules by security risk with high-risk rules prioritized
#
# Dangerous sudo commands detection based on GTFOBins (https://gtfobins.github.io/)
# GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions

set -euo pipefail

# Configuration
LOG_FILE="/var/log/get_sudoers.log"
ENABLE_LOGGING=${ENABLE_LOGGING:-false}

# Column width configuration
ENTITY_WIDTH=10
TYPE_WIDTH=6
PERMISSIONS_WIDTH=25
COMMANDS_WIDTH=25
FLAGS_WIDTH=40

# Arrays to store sudoers entries by category
declare -a high_risk_rules
declare -a group_privileges
declare -a user_privileges

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

# Main function
main() {
    log "Starting sudoers enumeration"
    enumerate_sudoers
}

# Run main function
main