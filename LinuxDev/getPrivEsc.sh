#!/bin/bash

# Privilege escalation enumeration script for security assessment
# Categorizes SUID binaries and capabilities by security risk
# 
# Exploitable binaries detection based on GTFOBins (https://gtfobins.github.io/)
# GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions

set -euo pipefail

# Configuration
LOG_FILE="/var/log/get_privesc.log"
ENABLE_LOGGING=${ENABLE_LOGGING:-false}

# Column width configuration
BINARY_WIDTH=35
OWNER_WIDTH=10
PERMISSIONS_WIDTH=12
CAPABILITIES_WIDTH=15
FLAGS_WIDTH=30

# Arrays to store findings by category
declare -a dangerous_suid
declare -a standard_suid
declare -a capabilities_binaries

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

# Main function
main() {
    log "Starting privilege escalation enumeration"
    enumerate_privilege_escalation
}

# Run main function
main