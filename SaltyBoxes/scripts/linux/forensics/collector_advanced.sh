#!/bin/bash
# ==============================================================================
# Advanced Forensic Artifact Collector v2.0
# Comprehensive DFIR collection following order of volatility
# Inspired by UAC, Velociraptor, and DFIR best practices
#
# Features:
#   - Memory forensics (process memory, /proc analysis)
#   - Timeline/bodyfile generation for temporal analysis
#   - File hashing with SHA-256 for integrity verification
#   - Rootkit detection (chkrootkit/rkhunter style checks)
#   - YARA scanning (if yara installed)
#   - Container forensics (Docker/Kubernetes)
#   - Comprehensive log collection with rotation handling
#   - Network flow analysis
#   - Syscall audit collection (auditd)
#
# Usage:
#   ./collector_advanced.sh <output_dir> [hostname] [timestamp]
#
# Output:
#   Creates comprehensive forensic tarball with structured artifacts
# ==============================================================================

set -uo pipefail

# Configuration
OUTPUT_DIR="${1:-/tmp/forensics_$(date +%Y%m%d_%H%M%S)}"
HOSTNAME="${2:-$(hostname)}"
TIMESTAMP="${3:-$(date +%Y%m%d_%H%M%S)}"
COMMAND_TIMEOUT=60
MAX_LOG_SIZE_MB=100
MAX_MEMORY_DUMP_MB=512
HASH_ALGORITHM="sha256"
COLLECT_MEMORY=true
COLLECT_TIMELINE=true
COLLECT_YARA=true
COLLECT_CONTAINERS=true

# Directories to hash for integrity verification
HASH_DIRS="/bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib /etc"

# Timeline directories (most important for forensic analysis)
TIMELINE_DIRS="/root /home /etc /var/log /tmp /var/tmp /opt /srv"

# Colors
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' CYAN='' NC=''
fi

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_phase() { echo -e "${CYAN}[====]${NC} $1"; }

# Safe command execution with timeout
safe_run() {
    local output_file="$1"
    local description="$2"
    shift 2
    log_info "Collecting: $description"
    if timeout "${COMMAND_TIMEOUT}" "$@" > "$output_file" 2>&1; then
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "# Command timed out after ${COMMAND_TIMEOUT}s" >> "$output_file"
            log_warn "Timeout: $description"
        fi
        return 0
    fi
}

# Safe file copy with size limit
safe_copy() {
    local src="$1"
    local dest="$2"
    local max_size="${3:-$((MAX_LOG_SIZE_MB * 1024 * 1024))}"
    if [ -f "$src" ]; then
        local size=$(stat -c%s "$src" 2>/dev/null || echo 0)
        if [ "$size" -gt "$max_size" ]; then
            tail -c "$max_size" "$src" > "$dest"
            echo "# Truncated to last $((max_size / 1024 / 1024))MB (was $size bytes)" | cat - "$dest" > "${dest}.tmp" && mv "${dest}.tmp" "$dest"
            log_warn "Truncated: $src"
        else
            cp "$src" "$dest" 2>/dev/null
        fi
        return 0
    fi
    return 1
}

# Detect OS family
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_FAMILY="${ID_LIKE:-$ID}"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_FAMILY="rhel fedora"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_FAMILY="debian"
    else
        OS_ID="unknown"
        OS_FAMILY="unknown"
    fi
}

# Check if command exists
has_cmd() { command -v "$1" &>/dev/null; }

# ==============================================================================
# PHASE 1: VOLATILE DATA (Highest priority - disappears first)
# ==============================================================================
collect_volatile() {
    log_phase "PHASE 1: VOLATILE DATA COLLECTION"
    local vol_dir="$OUTPUT_DIR/volatile"
    mkdir -p "$vol_dir"

    # System time (critical for timeline correlation)
    log_info "Collecting: system time and timezone"
    {
        echo "=== Collection Start Time ==="
        date -Iseconds
        date +%s
        echo ""
        echo "=== Timezone ==="
        cat /etc/timezone 2>/dev/null || timedatectl 2>/dev/null || date +%Z
        echo ""
        echo "=== Hardware Clock ==="
        hwclock --show 2>/dev/null || echo "hwclock not available"
        echo ""
        echo "=== NTP Status ==="
        timedatectl show 2>/dev/null || ntpq -p 2>/dev/null || chronyc tracking 2>/dev/null || echo "NTP status unavailable"
    } > "$vol_dir/system_time.txt"

    # Running processes (full detail)
    safe_run "$vol_dir/ps_auxwwf.txt" "process tree (full)" ps auxwwf
    safe_run "$vol_dir/ps_aux.txt" "process list" ps aux
    safe_run "$vol_dir/pstree_p.txt" "process tree with PIDs" pstree -p 2>/dev/null

    # Open files and handles
    safe_run "$vol_dir/lsof_full.txt" "open files (full)" lsof -n 2>/dev/null

    # Network connections (current state)
    safe_run "$vol_dir/ss_all.txt" "all sockets" ss -anpeum
    safe_run "$vol_dir/netstat_all.txt" "netstat connections" netstat -anpeu 2>/dev/null

    # Network interfaces and routing
    safe_run "$vol_dir/ip_addr.txt" "IP addresses" ip -d addr
    safe_run "$vol_dir/ip_route.txt" "routing table" ip route show table all
    safe_run "$vol_dir/ip_neigh.txt" "ARP table" ip neigh
    safe_run "$vol_dir/ip_link.txt" "link status" ip -s link

    # Loaded kernel modules
    safe_run "$vol_dir/lsmod.txt" "loaded modules" lsmod
    safe_run "$vol_dir/modules_params.txt" "module parameters" cat /proc/modules

    # Mount points
    safe_run "$vol_dir/mount.txt" "mounted filesystems" mount -l
    safe_run "$vol_dir/df.txt" "disk usage" df -hT

    # Memory info
    safe_run "$vol_dir/meminfo.txt" "memory info" cat /proc/meminfo
    safe_run "$vol_dir/vmstat.txt" "VM statistics" vmstat -s

    # System uptime and load
    safe_run "$vol_dir/uptime.txt" "uptime" uptime
    safe_run "$vol_dir/loadavg.txt" "load average" cat /proc/loadavg
}

# ==============================================================================
# PHASE 2: MEMORY FORENSICS
# ==============================================================================
collect_memory() {
    [ "$COLLECT_MEMORY" != "true" ] && return
    log_phase "PHASE 2: MEMORY FORENSICS"
    local mem_dir="$OUTPUT_DIR/memory"
    mkdir -p "$mem_dir"

    # Process memory maps for all processes
    log_info "Collecting: process memory maps"
    mkdir -p "$mem_dir/proc_maps"
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        if [ -r "$pid/maps" ]; then
            {
                echo "=== Process: $(cat $pid/comm 2>/dev/null || echo 'unknown') (PID: $pid_num) ==="
                echo "=== Command: $(tr '\0' ' ' < $pid/cmdline 2>/dev/null) ==="
                cat "$pid/maps" 2>/dev/null
            } > "$mem_dir/proc_maps/${pid_num}_maps.txt" 2>/dev/null
        fi
    done

    # Process environment variables (can contain credentials)
    log_info "Collecting: process environments"
    mkdir -p "$mem_dir/proc_environ"
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        if [ -r "$pid/environ" ]; then
            {
                echo "=== Process: $(cat $pid/comm 2>/dev/null) (PID: $pid_num) ==="
                tr '\0' '\n' < "$pid/environ" 2>/dev/null
            } > "$mem_dir/proc_environ/${pid_num}_env.txt" 2>/dev/null
        fi
    done

    # Process file descriptors
    log_info "Collecting: process file descriptors"
    mkdir -p "$mem_dir/proc_fd"
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        if [ -d "$pid/fd" ]; then
            ls -la "$pid/fd" 2>/dev/null > "$mem_dir/proc_fd/${pid_num}_fd.txt"
        fi
    done

    # Deleted files still open (malware hiding technique)
    log_info "Collecting: deleted but open files"
    find /proc/*/fd -ls 2>/dev/null | grep '(deleted)' > "$mem_dir/deleted_open_files.txt"

    # /proc/kcore info (don't dump full - too large)
    log_info "Collecting: kernel memory layout"
    if [ -r /proc/kcore ]; then
        file /proc/kcore > "$mem_dir/kcore_info.txt" 2>&1
        readelf -h /proc/kcore >> "$mem_dir/kcore_info.txt" 2>&1 || true
    fi

    # Kernel symbols
    safe_copy /proc/kallsyms "$mem_dir/kallsyms.txt" $((50 * 1024 * 1024))

    # Process memory dumps for suspicious processes (processes in /tmp, /dev, etc.)
    log_info "Collecting: suspicious process memory"
    mkdir -p "$mem_dir/suspicious_procs"
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        exe_path=$(readlink "$pid/exe" 2>/dev/null || echo "")
        # Check if running from suspicious location
        if echo "$exe_path" | grep -qE '^/(tmp|var/tmp|dev/shm|dev/|home/.*/.*)'; then
            log_warn "Suspicious process found: PID $pid_num ($exe_path)"
            {
                echo "=== Suspicious Process ==="
                echo "PID: $pid_num"
                echo "Exe: $exe_path"
                echo "Cmdline: $(tr '\0' ' ' < $pid/cmdline 2>/dev/null)"
                echo "Cwd: $(readlink $pid/cwd 2>/dev/null)"
                echo ""
                echo "=== Maps ==="
                cat "$pid/maps" 2>/dev/null
                echo ""
                echo "=== Status ==="
                cat "$pid/status" 2>/dev/null
            } > "$mem_dir/suspicious_procs/${pid_num}_full.txt"

            # Try to dump process memory with gcore
            if has_cmd gcore; then
                timeout 30 gcore -o "$mem_dir/suspicious_procs/${pid_num}_core" "$pid_num" 2>/dev/null || true
            fi
        fi
    done

    # Shared memory segments
    safe_run "$mem_dir/ipcs_shm.txt" "shared memory" ipcs -m
    safe_run "$mem_dir/ipcs_all.txt" "all IPC" ipcs -a
}

# ==============================================================================
# PHASE 3: TIMELINE / BODYFILE GENERATION
# ==============================================================================
collect_timeline() {
    [ "$COLLECT_TIMELINE" != "true" ] && return
    log_phase "PHASE 3: TIMELINE GENERATION"
    local tl_dir="$OUTPUT_DIR/timeline"
    mkdir -p "$tl_dir"

    # Generate bodyfile format (compatible with mactime)
    # Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    log_info "Generating: filesystem bodyfile (this may take a while)"

    # Create bodyfile from key directories
    {
        echo "# Bodyfile generated at $(date -Iseconds)"
        echo "# Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime"

        for dir in $TIMELINE_DIRS; do
            [ -d "$dir" ] || continue
            find "$dir" -xdev -printf '0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n' 2>/dev/null
        done
    } > "$tl_dir/filesystem.bodyfile"

    # Also create bodyfile for system directories
    log_info "Generating: system directories bodyfile"
    {
        for dir in /bin /sbin /usr/bin /usr/sbin /lib /lib64 /etc; do
            [ -d "$dir" ] || continue
            find "$dir" -xdev -printf '0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n' 2>/dev/null
        done
    } > "$tl_dir/system.bodyfile"

    # Generate human-readable timeline
    log_info "Generating: human-readable timeline"
    {
        echo "# Recent file modifications (last 7 days)"
        echo "# Format: mtime|atime|ctime|size|path"
        for dir in $TIMELINE_DIRS /bin /sbin /usr/bin /usr/sbin /etc; do
            [ -d "$dir" ] || continue
            find "$dir" -xdev -mtime -7 -printf '%T@|%A@|%C@|%s|%p\n' 2>/dev/null
        done | sort -rn | head -10000
    } > "$tl_dir/recent_modifications.txt"

    # Timeline of executable changes
    log_info "Generating: executable modification timeline"
    {
        echo "# Modified executables in last 30 days"
        find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
            -type f -mtime -30 -printf '%T+ %M %u:%g %s %p\n' 2>/dev/null | sort -r
    } > "$tl_dir/executable_changes.txt"

    # Boot timeline
    log_info "Collecting: boot timeline"
    {
        echo "=== Boot Times ==="
        who -b
        echo ""
        echo "=== Reboot History ==="
        last reboot | head -50
        echo ""
        echo "=== Shutdown History ==="
        last shutdown | head -50
    } > "$tl_dir/boot_history.txt"

    # Login timeline
    log_info "Collecting: login timeline"
    {
        echo "=== Recent Logins ==="
        last -100
        echo ""
        echo "=== Failed Logins ==="
        lastb 2>/dev/null | head -100 || echo "lastb not available or no permissions"
        echo ""
        echo "=== Currently Logged In ==="
        w
    } > "$tl_dir/login_history.txt"
}

# ==============================================================================
# PHASE 4: FILE HASHING FOR INTEGRITY
# ==============================================================================
collect_hashes() {
    log_phase "PHASE 4: FILE INTEGRITY HASHING"
    local hash_dir="$OUTPUT_DIR/hashes"
    mkdir -p "$hash_dir"

    # Hash critical system binaries
    log_info "Hashing: system binaries (SHA-256)"
    {
        echo "# SHA-256 hashes generated at $(date -Iseconds)"
        echo "# Use: sha256sum -c hashes.sha256 to verify"
        for dir in /bin /sbin /usr/bin /usr/sbin; do
            [ -d "$dir" ] || continue
            find "$dir" -maxdepth 1 -type f -exec sha256sum {} \; 2>/dev/null
        done
    } > "$hash_dir/binaries.sha256"

    # Hash libraries
    log_info "Hashing: shared libraries"
    {
        for dir in /lib /lib64 /usr/lib /usr/lib64; do
            [ -d "$dir" ] || continue
            find "$dir" -maxdepth 2 -name "*.so*" -type f -exec sha256sum {} \; 2>/dev/null
        done
    } > "$hash_dir/libraries.sha256"

    # Hash configuration files
    log_info "Hashing: configuration files"
    find /etc -maxdepth 2 -type f -size -1M -exec sha256sum {} \; 2>/dev/null > "$hash_dir/etc_configs.sha256"

    # Hash suspicious files found
    log_info "Hashing: suspicious files"
    {
        # Hidden files in temp directories
        find /tmp /var/tmp /dev/shm -name ".*" -type f -exec sha256sum {} \; 2>/dev/null
        # Executables in unusual locations
        find /tmp /var/tmp /dev/shm /home -type f -executable -exec sha256sum {} \; 2>/dev/null
    } > "$hash_dir/suspicious_files.sha256"

    # Package verification
    log_info "Verifying: package integrity"
    if has_cmd debsums; then
        debsums -c 2>/dev/null > "$hash_dir/debsums_changed.txt" || true
    fi
    if has_cmd rpm; then
        rpm -Va 2>/dev/null > "$hash_dir/rpm_verify.txt" || true
    fi
}

# ==============================================================================
# PHASE 5: ROOTKIT DETECTION
# ==============================================================================
collect_rootkit_checks() {
    log_phase "PHASE 5: ROOTKIT DETECTION"
    local rk_dir="$OUTPUT_DIR/rootkit_detection"
    mkdir -p "$rk_dir"

    # Check ld.so.preload
    log_info "Checking: ld.so.preload"
    {
        echo "=== /etc/ld.so.preload ==="
        if [ -f /etc/ld.so.preload ]; then
            echo "WARNING: ld.so.preload EXISTS"
            cat /etc/ld.so.preload
        else
            echo "OK: File does not exist (normal)"
        fi
    } > "$rk_dir/ld_preload.txt"

    # Hidden processes (compare ps with /proc)
    log_info "Checking: hidden processes"
    {
        echo "=== Hidden Process Detection ==="
        echo "Processes in /proc but not in ps:"
        comm -23 <(ls -1 /proc | grep '^[0-9]*$' | sort -n) \
                 <(ps -eo pid --no-headers | tr -d ' ' | sort -n) 2>/dev/null
        echo ""
        echo "Process count comparison:"
        echo "  /proc count: $(ls -1 /proc | grep -c '^[0-9]*$')"
        echo "  ps count: $(ps -eo pid --no-headers | wc -l)"
    } > "$rk_dir/hidden_processes.txt"

    # Processes running from deleted files
    log_info "Checking: deleted executables"
    {
        echo "=== Processes Running from Deleted Files ==="
        ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'
    } > "$rk_dir/deleted_executables.txt"

    # Processes running from suspicious locations
    log_info "Checking: suspicious process locations"
    {
        echo "=== Processes in Suspicious Locations ==="
        for pid in /proc/[0-9]*; do
            exe=$(readlink "$pid/exe" 2>/dev/null || continue)
            if echo "$exe" | grep -qE '^/(tmp|var/tmp|dev/shm|dev/|\.|\s)'; then
                pid_num=$(basename "$pid")
                echo "PID $pid_num: $exe"
                echo "  Cmdline: $(tr '\0' ' ' < $pid/cmdline 2>/dev/null)"
            fi
        done
    } > "$rk_dir/suspicious_locations.txt"

    # Kernel module verification
    log_info "Checking: kernel modules"
    {
        echo "=== Loaded Kernel Modules ==="
        lsmod
        echo ""
        echo "=== Module Files vs Loaded ==="
        for mod in $(lsmod | awk 'NR>1 {print $1}'); do
            modpath=$(modinfo -n "$mod" 2>/dev/null || echo "NOT FOUND")
            echo "$mod: $modpath"
        done
    } > "$rk_dir/kernel_modules.txt"

    # Check for common rootkit files/directories
    log_info "Checking: known rootkit indicators"
    {
        echo "=== Known Rootkit File Check ==="
        rootkit_paths=(
            "/usr/lib/libproc.a"
            "/dev/.static"
            "/dev/.rd"
            "/dev/.hd"
            "/dev/.pts"
            "/etc/ld.so.hash"
            "/lib/security/.config"
            "/usr/include/.. "
            "/usr/include/.../"
        )
        for path in "${rootkit_paths[@]}"; do
            if [ -e "$path" ]; then
                echo "WARNING: Found $path"
                ls -la "$path" 2>/dev/null
            fi
        done
        echo "Scan complete"
    } > "$rk_dir/known_rootkits.txt"

    # Check for suspicious SUID binaries
    log_info "Checking: SUID/SGID binaries"
    {
        echo "=== SUID Binaries ==="
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%M %u:%g %p\n' 2>/dev/null
        echo ""
        echo "=== SUID in Non-Standard Locations ==="
        find /tmp /var/tmp /dev/shm /home /opt -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
    } > "$rk_dir/suid_binaries.txt"

    # Check listening ports against expected
    log_info "Checking: unusual listeners"
    {
        echo "=== All Listening Ports ==="
        ss -tlnp
        echo ""
        echo "=== Potentially Suspicious Ports ==="
        # Common backdoor ports
        for port in 4444 4445 4446 5555 6666 6667 1337 31337 12345 23456; do
            if ss -tln | grep -q ":$port "; then
                echo "WARNING: Listener on port $port"
                ss -tlnp | grep ":$port "
            fi
        done
    } > "$rk_dir/listening_ports.txt"

    # Run chkrootkit if available
    if has_cmd chkrootkit; then
        log_info "Running: chkrootkit"
        timeout 300 chkrootkit 2>/dev/null > "$rk_dir/chkrootkit.txt" || true
    fi

    # Run rkhunter if available
    if has_cmd rkhunter; then
        log_info "Running: rkhunter"
        timeout 300 rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null > "$rk_dir/rkhunter.txt" || true
    fi
}

# ==============================================================================
# PHASE 6: YARA SCANNING
# ==============================================================================
collect_yara() {
    [ "$COLLECT_YARA" != "true" ] && return
    has_cmd yara || return

    log_phase "PHASE 6: YARA MALWARE SCANNING"
    local yara_dir="$OUTPUT_DIR/yara_scan"
    mkdir -p "$yara_dir"

    # Check for YARA rules
    local rules_found=false
    local rules_file=""
    for rules_path in /etc/yara/rules.yar /opt/yara-rules/index.yar /usr/share/yara/*.yar; do
        if [ -f "$rules_path" ]; then
            rules_file="$rules_path"
            rules_found=true
            break
        fi
    done

    if [ "$rules_found" = false ]; then
        echo "No YARA rules found. Install rules to /etc/yara/rules.yar for scanning." > "$yara_dir/no_rules.txt"
        return
    fi

    log_info "YARA scanning with rules: $rules_file"

    # Scan suspicious directories
    {
        echo "=== YARA Scan Results ==="
        echo "Rules: $rules_file"
        echo "Scan time: $(date -Iseconds)"
        echo ""
        for scan_dir in /tmp /var/tmp /dev/shm /home /opt /var/www; do
            [ -d "$scan_dir" ] || continue
            echo "--- Scanning: $scan_dir ---"
            timeout 300 yara -r "$rules_file" "$scan_dir" 2>/dev/null || true
        done
    } > "$yara_dir/scan_results.txt"
}

# ==============================================================================
# PHASE 7: CONTAINER FORENSICS
# ==============================================================================
collect_containers() {
    [ "$COLLECT_CONTAINERS" != "true" ] && return
    log_phase "PHASE 7: CONTAINER FORENSICS"
    local cont_dir="$OUTPUT_DIR/containers"
    mkdir -p "$cont_dir"

    # Docker forensics
    if has_cmd docker && docker info &>/dev/null; then
        log_info "Collecting: Docker artifacts"
        mkdir -p "$cont_dir/docker"

        docker ps -a --no-trunc > "$cont_dir/docker/containers.txt" 2>/dev/null
        docker images --no-trunc > "$cont_dir/docker/images.txt" 2>/dev/null
        docker network ls > "$cont_dir/docker/networks.txt" 2>/dev/null
        docker volume ls > "$cont_dir/docker/volumes.txt" 2>/dev/null

        # Detailed container info
        for cid in $(docker ps -aq 2>/dev/null); do
            docker inspect "$cid" > "$cont_dir/docker/container_${cid}.json" 2>/dev/null
            docker logs --tail 1000 "$cid" > "$cont_dir/docker/logs_${cid}.txt" 2>/dev/null
        done

        # Docker daemon config
        safe_copy /etc/docker/daemon.json "$cont_dir/docker/daemon.json"
    fi

    # Kubernetes forensics
    if has_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
        log_info "Collecting: Kubernetes artifacts"
        mkdir -p "$cont_dir/kubernetes"

        kubectl cluster-info > "$cont_dir/kubernetes/cluster_info.txt" 2>/dev/null
        kubectl get nodes -o wide > "$cont_dir/kubernetes/nodes.txt" 2>/dev/null
        kubectl get pods -A -o wide > "$cont_dir/kubernetes/pods.txt" 2>/dev/null
        kubectl get services -A > "$cont_dir/kubernetes/services.txt" 2>/dev/null
        kubectl get events -A --sort-by='.lastTimestamp' > "$cont_dir/kubernetes/events.txt" 2>/dev/null
    fi

    # Podman
    if has_cmd podman; then
        log_info "Collecting: Podman artifacts"
        mkdir -p "$cont_dir/podman"
        podman ps -a > "$cont_dir/podman/containers.txt" 2>/dev/null
        podman images > "$cont_dir/podman/images.txt" 2>/dev/null
    fi
}

# ==============================================================================
# PHASE 8: COMPREHENSIVE LOG COLLECTION
# ==============================================================================
collect_logs() {
    log_phase "PHASE 8: COMPREHENSIVE LOG COLLECTION"
    local log_dir="$OUTPUT_DIR/logs"
    mkdir -p "$log_dir"/{system,auth,audit,applications}

    # System logs
    log_info "Collecting: system logs"
    safe_copy /var/log/syslog "$log_dir/system/syslog"
    safe_copy /var/log/messages "$log_dir/system/messages"
    safe_copy /var/log/kern.log "$log_dir/system/kern.log"
    safe_copy /var/log/dmesg "$log_dir/system/dmesg_file"
    dmesg -T > "$log_dir/system/dmesg_current.txt" 2>/dev/null

    # Full journal export
    log_info "Collecting: systemd journal"
    if has_cmd journalctl; then
        journalctl --no-pager -n 50000 > "$log_dir/system/journal_full.txt" 2>/dev/null
        journalctl --no-pager -k -n 10000 > "$log_dir/system/journal_kernel.txt" 2>/dev/null
    fi

    # Auth logs (with rotations)
    log_info "Collecting: authentication logs"
    for logfile in /var/log/auth.log* /var/log/secure*; do
        [ -f "$logfile" ] || continue
        base=$(basename "$logfile")
        if [[ "$logfile" == *.gz ]]; then
            zcat "$logfile" > "$log_dir/auth/${base%.gz}" 2>/dev/null
        else
            safe_copy "$logfile" "$log_dir/auth/$base"
        fi
    done

    # Audit logs
    log_info "Collecting: audit logs"
    if [ -d /var/log/audit ]; then
        for auditlog in /var/log/audit/audit.log*; do
            [ -f "$auditlog" ] || continue
            base=$(basename "$auditlog")
            safe_copy "$auditlog" "$log_dir/audit/$base"
        done
    fi
    auditctl -l > "$log_dir/audit/audit_rules.txt" 2>/dev/null
    auditctl -s > "$log_dir/audit/audit_status.txt" 2>/dev/null

    # Application logs
    log_info "Collecting: application logs"

    # SSH
    safe_copy /var/log/sshd.log "$log_dir/applications/sshd.log"

    # Web servers
    for weblog in /var/log/apache2/*.log /var/log/httpd/*.log /var/log/nginx/*.log; do
        [ -f "$weblog" ] || continue
        base=$(basename "$weblog")
        dir=$(basename $(dirname "$weblog"))
        mkdir -p "$log_dir/applications/$dir"
        safe_copy "$weblog" "$log_dir/applications/$dir/$base"
    done

    # Databases
    for dblog in /var/log/mysql/*.log /var/log/postgresql/*.log /var/lib/mysql/*.log; do
        [ -f "$dblog" ] || continue
        base=$(basename "$dblog")
        safe_copy "$dblog" "$log_dir/applications/$base"
    done

    # Package manager logs
    safe_copy /var/log/dpkg.log "$log_dir/system/dpkg.log"
    safe_copy /var/log/yum.log "$log_dir/system/yum.log"
    safe_copy /var/log/dnf.log "$log_dir/system/dnf.log"
    safe_copy /var/log/apt/history.log "$log_dir/system/apt_history.log"

    # Fail2ban
    safe_copy /var/log/fail2ban.log "$log_dir/applications/fail2ban.log"
}

# ==============================================================================
# PHASE 9: PERSISTENCE MECHANISMS
# ==============================================================================
collect_persistence() {
    log_phase "PHASE 9: PERSISTENCE MECHANISMS"
    local pers_dir="$OUTPUT_DIR/persistence"
    mkdir -p "$pers_dir"/{cron,systemd,init}

    # Cron (comprehensive)
    log_info "Collecting: cron jobs"
    safe_copy /etc/crontab "$pers_dir/cron/crontab"
    cp -r /etc/cron.d "$pers_dir/cron/" 2>/dev/null
    cp -r /etc/cron.daily "$pers_dir/cron/" 2>/dev/null
    cp -r /etc/cron.hourly "$pers_dir/cron/" 2>/dev/null
    cp -r /etc/cron.weekly "$pers_dir/cron/" 2>/dev/null
    cp -r /etc/cron.monthly "$pers_dir/cron/" 2>/dev/null

    # User crontabs
    {
        echo "=== User Crontabs ==="
        for user in $(cut -d: -f1 /etc/passwd); do
            crontab -l -u "$user" 2>/dev/null && echo "--- User: $user ---"
        done
    } > "$pers_dir/cron/user_crontabs.txt"

    # Systemd services
    log_info "Collecting: systemd services"
    systemctl list-unit-files --type=service > "$pers_dir/systemd/services_all.txt" 2>/dev/null
    systemctl list-units --type=service --state=running > "$pers_dir/systemd/services_running.txt" 2>/dev/null
    systemctl list-timers --all > "$pers_dir/systemd/timers.txt" 2>/dev/null

    # Custom/suspicious services
    mkdir -p "$pers_dir/systemd/custom_services"
    for svc_dir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [ -d "$svc_dir" ] || continue
        find "$svc_dir" -maxdepth 1 -name "*.service" -newer /var/lib/dpkg/info 2>/dev/null -exec cp {} "$pers_dir/systemd/custom_services/" \; 2>/dev/null || \
        find "$svc_dir" -maxdepth 1 -name "*.service" -mtime -30 -exec cp {} "$pers_dir/systemd/custom_services/" \; 2>/dev/null
    done

    # Init scripts
    log_info "Collecting: init scripts"
    ls -la /etc/init.d/ > "$pers_dir/init/init.d_listing.txt" 2>/dev/null
    cp -r /etc/init.d "$pers_dir/init/" 2>/dev/null
    safe_copy /etc/rc.local "$pers_dir/init/rc.local"
    safe_copy /etc/rc.d/rc.local "$pers_dir/init/rc.d_rc.local"

    # AT jobs
    log_info "Collecting: at jobs"
    atq > "$pers_dir/at_queue.txt" 2>/dev/null
    ls -la /var/spool/at/ > "$pers_dir/at_spool.txt" 2>/dev/null

    # Systemd user services
    for home in /root /home/*; do
        [ -d "$home/.config/systemd/user" ] && cp -r "$home/.config/systemd/user" "$pers_dir/systemd/user_$(basename $home)/" 2>/dev/null
    done
}

# ==============================================================================
# PHASE 10: USER ARTIFACTS
# ==============================================================================
collect_users() {
    log_phase "PHASE 10: USER ARTIFACTS"
    local user_dir="$OUTPUT_DIR/users"
    mkdir -p "$user_dir"/{ssh_keys,histories,configs}

    # Core user files
    safe_copy /etc/passwd "$user_dir/passwd"
    safe_copy /etc/shadow "$user_dir/shadow"
    safe_copy /etc/group "$user_dir/group"
    safe_copy /etc/gshadow "$user_dir/gshadow"
    safe_copy /etc/sudoers "$user_dir/sudoers"
    cp -r /etc/sudoers.d "$user_dir/" 2>/dev/null

    # SSH keys for all users
    log_info "Collecting: SSH keys"
    {
        for home in /root /home/*; do
            [ -d "$home/.ssh" ] || continue
            user=$(basename "$home")
            echo "=== User: $user ==="
            for keyfile in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
                [ -f "$keyfile" ] && cat "$keyfile"
            done
            echo ""
        done
    } > "$user_dir/ssh_keys/authorized_keys_all.txt"

    # Copy all SSH directories
    for home in /root /home/*; do
        [ -d "$home/.ssh" ] || continue
        user=$(basename "$home")
        cp -r "$home/.ssh" "$user_dir/ssh_keys/$user/" 2>/dev/null
    done

    # Shell histories
    log_info "Collecting: shell histories"
    for home in /root /home/*; do
        user=$(basename "$home")
        for hist in .bash_history .zsh_history .sh_history .history; do
            [ -f "$home/$hist" ] && safe_copy "$home/$hist" "$user_dir/histories/${user}_${hist}"
        done
    done

    # Shell configs (potential backdoors)
    log_info "Collecting: shell configs"
    for home in /root /home/*; do
        user=$(basename "$home")
        for conf in .bashrc .bash_profile .profile .zshrc .vimrc; do
            [ -f "$home/$conf" ] && safe_copy "$home/$conf" "$user_dir/configs/${user}_${conf}"
        done
    done

    # Profile.d scripts
    cp -r /etc/profile.d "$user_dir/configs/" 2>/dev/null
    safe_copy /etc/profile "$user_dir/configs/etc_profile"
    safe_copy /etc/bash.bashrc "$user_dir/configs/etc_bash.bashrc"
}

# ==============================================================================
# PHASE 11: NETWORK FORENSICS
# ==============================================================================
collect_network() {
    log_phase "PHASE 11: NETWORK FORENSICS"
    local net_dir="$OUTPUT_DIR/network"
    mkdir -p "$net_dir"/{firewall,flows}

    # Current connections (already in volatile, but more detail here)
    log_info "Collecting: network connections"
    {
        echo "=== Active Connections with Process Info ==="
        ss -anptu
        echo ""
        echo "=== Listening Services ==="
        ss -tlnp
        echo ""
        echo "=== UDP Listeners ==="
        ss -ulnp
        echo ""
        echo "=== Unix Sockets ==="
        ss -xp
    } > "$net_dir/connections_full.txt"

    # Connection statistics
    safe_run "$net_dir/netstat_stats.txt" "network statistics" netstat -s

    # Firewall rules (comprehensive)
    log_info "Collecting: firewall rules"
    iptables-save > "$net_dir/firewall/iptables_save.txt" 2>/dev/null
    ip6tables-save > "$net_dir/firewall/ip6tables_save.txt" 2>/dev/null
    nft list ruleset > "$net_dir/firewall/nftables.txt" 2>/dev/null
    firewall-cmd --list-all-zones > "$net_dir/firewall/firewalld.txt" 2>/dev/null
    ufw status verbose > "$net_dir/firewall/ufw.txt" 2>/dev/null

    # DNS configuration
    safe_copy /etc/resolv.conf "$net_dir/resolv.conf"
    safe_copy /etc/hosts "$net_dir/hosts"
    safe_copy /etc/nsswitch.conf "$net_dir/nsswitch.conf"

    # Network interfaces detailed
    log_info "Collecting: interface details"
    {
        echo "=== Interface Statistics ==="
        ip -s link
        echo ""
        echo "=== Interface Addresses ==="
        ip -d addr
        echo ""
        echo "=== Interface Details ==="
        for iface in /sys/class/net/*; do
            name=$(basename "$iface")
            echo "--- $name ---"
            cat "$iface/address" 2>/dev/null
            cat "$iface/operstate" 2>/dev/null
            cat "$iface/speed" 2>/dev/null
        done
    } > "$net_dir/interfaces_detail.txt"

    # Packet capture (if tcpdump available and permitted)
    if has_cmd tcpdump && [ -w /tmp ]; then
        log_info "Capturing: network packets (10 seconds)"
        timeout 10 tcpdump -i any -c 1000 -w "$net_dir/capture.pcap" 2>/dev/null &
        wait
    fi
}

# ==============================================================================
# PHASE 12: SYSTEM CONFIGURATION
# ==============================================================================
collect_system() {
    log_phase "PHASE 12: SYSTEM CONFIGURATION"
    local sys_dir="$OUTPUT_DIR/system"
    mkdir -p "$sys_dir"

    # Basic system info
    safe_run "$sys_dir/hostname.txt" "hostname" hostname -f
    safe_run "$sys_dir/uname.txt" "kernel info" uname -a
    safe_copy /etc/os-release "$sys_dir/os-release"
    safe_copy /etc/machine-id "$sys_dir/machine-id"

    # Hardware info
    safe_run "$sys_dir/lscpu.txt" "CPU info" lscpu
    safe_run "$sys_dir/lspci.txt" "PCI devices" lspci -v
    safe_run "$sys_dir/lsusb.txt" "USB devices" lsusb -v
    safe_run "$sys_dir/dmidecode.txt" "DMI/BIOS" dmidecode 2>/dev/null

    # Kernel parameters
    safe_run "$sys_dir/sysctl.txt" "sysctl settings" sysctl -a
    safe_copy /proc/cmdline "$sys_dir/cmdline"

    # Installed packages
    log_info "Collecting: installed packages"
    if has_cmd dpkg; then
        dpkg -l > "$sys_dir/packages_dpkg.txt" 2>/dev/null
        dpkg --get-selections > "$sys_dir/packages_selections.txt" 2>/dev/null
    fi
    if has_cmd rpm; then
        rpm -qa --last > "$sys_dir/packages_rpm.txt" 2>/dev/null
    fi
    if has_cmd apk; then
        apk list -I > "$sys_dir/packages_apk.txt" 2>/dev/null
    fi

    # Repositories
    safe_copy /etc/apt/sources.list "$sys_dir/apt_sources.list"
    cp -r /etc/apt/sources.list.d "$sys_dir/" 2>/dev/null
    cp -r /etc/yum.repos.d "$sys_dir/" 2>/dev/null
}

# ==============================================================================
# PHASE 13: SUSPICIOUS FILES
# ==============================================================================
collect_suspicious() {
    log_phase "PHASE 13: SUSPICIOUS FILE DETECTION"
    local susp_dir="$OUTPUT_DIR/suspicious"
    mkdir -p "$susp_dir"

    # Hidden files in temp directories
    log_info "Finding: hidden files in temp"
    find /tmp /var/tmp /dev/shm -name ".*" -type f -ls 2>/dev/null > "$susp_dir/hidden_temp.txt"

    # Executables in temp directories
    log_info "Finding: executables in temp"
    find /tmp /var/tmp /dev/shm -type f -executable -ls 2>/dev/null > "$susp_dir/exec_temp.txt"

    # World-writable files in system directories
    log_info "Finding: world-writable system files"
    find /etc /bin /sbin /usr/bin /usr/sbin -xdev -type f -perm -0002 -ls 2>/dev/null > "$susp_dir/world_writable.txt"

    # Files with no user/group
    log_info "Finding: orphaned files"
    find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null | head -1000 > "$susp_dir/orphaned.txt"

    # Recently modified in system directories
    log_info "Finding: recently modified system files"
    find /bin /sbin /usr/bin /usr/sbin /lib /lib64 /etc -xdev -type f -mtime -7 -ls 2>/dev/null > "$susp_dir/recently_modified.txt"

    # Unusual file extensions in web directories
    log_info "Finding: suspicious web files"
    find /var/www /srv/www /usr/share/nginx/html -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp*" \) -mtime -30 -ls 2>/dev/null > "$susp_dir/web_scripts.txt"

    # Large files in /tmp
    log_info "Finding: large temp files"
    find /tmp /var/tmp -type f -size +100M -ls 2>/dev/null > "$susp_dir/large_temp.txt"
}

# ==============================================================================
# FINALIZE
# ==============================================================================
finalize() {
    log_phase "FINALIZING COLLECTION"

    # Create metadata
    log_info "Creating: metadata"
    cat > "$OUTPUT_DIR/metadata.json" << EOF
{
    "hostname": "$HOSTNAME",
    "collection_timestamp": "$TIMESTAMP",
    "collection_time_iso": "$(date -Iseconds)",
    "collector_version": "2.0-advanced",
    "os_id": "$OS_ID",
    "os_family": "$OS_FAMILY",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "features": {
        "memory_forensics": $COLLECT_MEMORY,
        "timeline_generation": $COLLECT_TIMELINE,
        "yara_scanning": $COLLECT_YARA,
        "container_forensics": $COLLECT_CONTAINERS,
        "hash_algorithm": "$HASH_ALGORITHM"
    },
    "phases_completed": [
        "volatile_data",
        "memory_forensics",
        "timeline_generation",
        "file_hashing",
        "rootkit_detection",
        "yara_scanning",
        "container_forensics",
        "log_collection",
        "persistence_mechanisms",
        "user_artifacts",
        "network_forensics",
        "system_configuration",
        "suspicious_files"
    ]
}
EOF

    # Hash the collection
    log_info "Hashing: collection integrity"
    find "$OUTPUT_DIR" -type f -exec sha256sum {} \; > "$OUTPUT_DIR/collection_manifest.sha256"

    # Create tarball
    local tarball="${OUTPUT_DIR}/${HOSTNAME}_forensics_${TIMESTAMP}.tar.gz"
    log_info "Creating: tarball"
    tar -czf "$tarball" -C "$(dirname $OUTPUT_DIR)" "$(basename $OUTPUT_DIR)" 2>/dev/null
    chmod 600 "$tarball"

    local size=$(stat -c%s "$tarball" 2>/dev/null || echo 0)
    local duration=$(($(date +%s) - START_TIME))

    echo ""
    echo "========================================"
    echo "ADVANCED FORENSIC COLLECTION COMPLETE"
    echo "========================================"
    echo "Host: $HOSTNAME"
    echo "Duration: $duration seconds"
    echo "Output: $tarball"
    echo "Size: $size bytes"
    echo "========================================"
    echo "TARBALL_PATH:$tarball"
}

# ==============================================================================
# MAIN
# ==============================================================================
main() {
    START_TIME=$(date +%s)

    echo "========================================"
    echo "ADVANCED FORENSIC ARTIFACT COLLECTOR v2.0"
    echo "========================================"
    echo "Host: $HOSTNAME"
    echo "Output: $OUTPUT_DIR"
    echo "Time: $(date -Iseconds)"
    echo "========================================"
    echo ""

    detect_os
    mkdir -p "$OUTPUT_DIR"

    # Execute all phases in order of volatility
    collect_volatile
    collect_memory
    collect_timeline
    collect_hashes
    collect_rootkit_checks
    collect_yara
    collect_containers
    collect_logs
    collect_persistence
    collect_users
    collect_network
    collect_system
    collect_suspicious
    finalize
}

main "$@"
