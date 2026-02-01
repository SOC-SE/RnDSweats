#!/bin/bash
# ==============================================================================
# COMPREHENSIVE FORENSIC COLLECTOR v3.0
# Enterprise-grade DFIR collection with memory forensics, kernel analysis,
# rootkit detection, and deep system inspection
#
# Features:
#   - Full memory dump (AVML/LiME/proc)
#   - Volatility 3 analysis (if available)
#   - Kernel rootkit detection
#   - Syscall table verification
#   - Hidden process detection
#   - Network namespace forensics
#   - Container escape detection
#   - Full timeline generation
#   - YARA malware scanning
#   - Comprehensive artifact collection
#
# Usage:
#   ./collector_forensic.sh <output_dir> <hostname> <timestamp> [options]
#
# Options:
#   --memory-dump     Enable full memory dump (requires root, large output)
#   --volatility      Run Volatility analysis on memory dump
#   --quick           Quick mode - skip slow operations
#   --no-logs         Skip log collection (faster)
#
# Output: Creates tarball with all forensic artifacts
# ==============================================================================

set -uo pipefail

# ==============================================================================
# CONFIGURATION
# ==============================================================================

OUTPUT_DIR="${1:-/tmp/forensics}"
HOSTNAME="${2:-$(hostname -s)}"
TIMESTAMP="${3:-$(date +%Y%m%d_%H%M%S)}"
shift 3 2>/dev/null || true

# Parse options
ENABLE_MEMORY_DUMP=false
ENABLE_VOLATILITY=false
QUICK_MODE=false
SKIP_LOGS=false
AUTO_INSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --memory-dump) ENABLE_MEMORY_DUMP=true ;;
        --volatility) ENABLE_VOLATILITY=true ;;
        --quick) QUICK_MODE=true ;;
        --no-logs) SKIP_LOGS=true ;;
        --auto-install) AUTO_INSTALL=true ;;
        *) ;;
    esac
    shift
done

COLLECTION_DIR="${OUTPUT_DIR}/${HOSTNAME}_forensics_${TIMESTAMP}"
TARBALL="${OUTPUT_DIR}/${HOSTNAME}_forensics_${TIMESTAMP}.tar.gz"

# Size limits
MAX_FILE_SIZE=$((100 * 1024 * 1024))  # 100MB per file
MAX_LOG_SIZE=$((50 * 1024 * 1024))    # 50MB per log
MAX_MEMORY_DUMP=$((8 * 1024 * 1024 * 1024))  # 8GB memory dump limit

# Timeouts
CMD_TIMEOUT=300
MEMORY_TIMEOUT=1800

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

log_phase() {
    echo "[====] $1"
}

log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1"
}

log_finding() {
    local severity="$1"
    local category="$2"
    local message="$3"
    echo "[FINDING:${severity}:${category}] $message"
    echo "${severity}|${category}|$(date -Iseconds)|${message}" >> "${COLLECTION_DIR}/findings.csv"
}

# Safe command execution with timeout
safe_exec() {
    local output_file="$1"
    shift
    timeout "$CMD_TIMEOUT" "$@" > "$output_file" 2>&1 || true
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_warn "Not running as root - some collection will be limited"
        return 1
    fi
    return 0
}

# Get available memory in bytes
get_available_memory() {
    awk '/MemTotal/ {print $2 * 1024}' /proc/meminfo
}

# Check if tool exists
has_tool() {
    command -v "$1" &>/dev/null
}

# ==============================================================================
# AUTO-INSTALL FORENSIC TOOLS
# ==============================================================================

# Detect package manager
detect_pkg_manager() {
    if has_tool apt-get; then
        echo "apt"
    elif has_tool dnf; then
        echo "dnf"
    elif has_tool yum; then
        echo "yum"
    elif has_tool zypper; then
        echo "zypper"
    elif has_tool pacman; then
        echo "pacman"
    elif has_tool apk; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# Install package based on package manager (with timeout and output)
install_pkg() {
    local pkg_manager="$1"
    shift
    local packages="$@"
    local timeout_sec=60
    local ret=0

    case "$pkg_manager" in
        apt)
            timeout "$timeout_sec" bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $packages" 2>&1 || ret=$?
            ;;
        dnf)
            timeout "$timeout_sec" dnf install -y --setopt=timeout=30 --setopt=retries=1 $packages 2>&1 || ret=$?
            ;;
        yum)
            timeout "$timeout_sec" yum install -y --setopt=timeout=30 --setopt=retries=1 $packages 2>&1 || ret=$?
            ;;
        zypper)
            timeout "$timeout_sec" zypper install -y -q $packages 2>&1 || ret=$?
            ;;
        pacman)
            timeout "$timeout_sec" pacman -S --noconfirm --quiet $packages 2>&1 || ret=$?
            ;;
        apk)
            timeout "$timeout_sec" apk add --quiet $packages 2>&1 || ret=$?
            ;;
    esac

    if [[ $ret -eq 124 ]]; then
        log_warn "  Package install timed out after ${timeout_sec}s: $packages"
    fi
    return $ret
}

# Check if a package is already installed (avoids slow install attempts)
pkg_installed() {
    local pkg_manager="$1"
    local pkg="$2"

    case "$pkg_manager" in
        apt)
            dpkg -s "$pkg" &>/dev/null
            ;;
        dnf|yum)
            rpm -q "$pkg" &>/dev/null
            ;;
        pacman)
            pacman -Qi "$pkg" &>/dev/null
            ;;
        apk)
            apk info -e "$pkg" &>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

# Install forensic tools if auto-install is enabled
install_forensic_tools() {
    if [[ "$AUTO_INSTALL" != "true" ]]; then
        return 0
    fi

    log_phase "AUTO-INSTALLING FORENSIC TOOLS"

    local pkg_manager=$(detect_pkg_manager)
    if [[ "$pkg_manager" == "unknown" ]]; then
        log_warn "Unknown package manager - skipping auto-install"
        return 1
    fi

    log_info "Detected package manager: $pkg_manager"

    # Disable broken/rogue repos that cause hangs (common in CCDC environments)
    if [[ "$pkg_manager" == "dnf" || "$pkg_manager" == "yum" ]]; then
        local bad_repos=0
        for repo in /etc/yum.repos.d/*.repo; do
            [[ -f "$repo" ]] || continue
            if grep -qE '(10\.13\.37|gpgcheck\s*=\s*0)' "$repo" 2>/dev/null; then
                local reponame=$(basename "$repo")
                log_warn "Disabling suspicious repo: $reponame"
                mv "$repo" "${repo}.disabled" 2>/dev/null || true
                ((bad_repos++))
            fi
        done
        [[ $bad_repos -gt 0 ]] && log_info "Disabled $bad_repos suspicious repo(s)"
    fi

    # Update package cache with timeout
    log_info "Updating package cache..."
    case "$pkg_manager" in
        apt)
            timeout 60 apt-get update -qq 2>&1 | tail -3 || log_warn "apt update timed out or failed"
            ;;
        dnf)
            timeout 60 dnf makecache --setopt=timeout=15 --setopt=retries=1 -q 2>&1 | tail -3 || log_warn "dnf cache update timed out or failed"
            timeout 30 dnf install -y --setopt=timeout=15 --setopt=retries=1 epel-release 2>&1 | tail -3 || true
            ;;
        yum)
            timeout 60 yum makecache --setopt=timeout=15 --setopt=retries=1 -q 2>&1 | tail -3 || log_warn "yum cache update timed out or failed"
            timeout 30 yum install -y --setopt=timeout=15 --setopt=retries=1 epel-release 2>&1 | tail -3 || true
            ;;
    esac

    local installed_count=0
    local skipped_count=0
    local failed_count=0

    # Build list of needed packages (skip already-installed)
    local essential_pkgs=""
    local forensic_pkgs=""

    case "$pkg_manager" in
        apt)
            essential_pkgs="net-tools lsof strace tcpdump procps psmisc iproute2 binutils coreutils findutils file acl attr"
            forensic_pkgs="chkrootkit rkhunter clamav auditd sysstat unhide debsums"
            ;;
        dnf|yum)
            essential_pkgs="net-tools lsof strace tcpdump procps-ng psmisc iproute binutils coreutils findutils file acl attr"
            forensic_pkgs="chkrootkit rkhunter clamav audit sysstat unhide"
            ;;
        *)
            essential_pkgs="net-tools lsof strace tcpdump procps psmisc iproute2 binutils file"
            forensic_pkgs="chkrootkit rkhunter sysstat"
            ;;
    esac

    # Filter to only packages not yet installed
    local to_install=""
    log_info "Checking essential tools..."
    for pkg in $essential_pkgs; do
        if pkg_installed "$pkg_manager" "$pkg"; then
            ((skipped_count++))
        else
            to_install="$to_install $pkg"
        fi
    done

    # Batch install essential tools
    if [[ -n "$to_install" ]]; then
        log_info "Installing essential tools:$to_install"
        if install_pkg "$pkg_manager" $to_install; then
            for pkg in $to_install; do
                if pkg_installed "$pkg_manager" "$pkg"; then
                    log_info "  [OK] $pkg"
                    ((installed_count++))
                else
                    log_warn "  [FAIL] $pkg"
                    ((failed_count++))
                fi
            done
        else
            log_warn "  Batch install failed, trying individually..."
            for pkg in $to_install; do
                if install_pkg "$pkg_manager" "$pkg" >/dev/null 2>&1; then
                    log_info "  [OK] $pkg"
                    ((installed_count++))
                else
                    log_warn "  [FAIL] $pkg"
                    ((failed_count++))
                fi
            done
        fi
    else
        log_info "All essential tools already installed ($skipped_count packages)"
    fi

    # Filter forensic tools
    to_install=""
    log_info "Checking forensic tools..."
    for pkg in $forensic_pkgs; do
        if pkg_installed "$pkg_manager" "$pkg"; then
            ((skipped_count++))
        else
            to_install="$to_install $pkg"
        fi
    done

    # Batch install forensic tools
    if [[ -n "$to_install" ]]; then
        log_info "Installing forensic tools:$to_install"
        if install_pkg "$pkg_manager" $to_install; then
            for pkg in $to_install; do
                if pkg_installed "$pkg_manager" "$pkg"; then
                    log_info "  [OK] $pkg"
                    ((installed_count++))
                else
                    log_warn "  [FAIL] $pkg (may not be in repos)"
                    ((failed_count++))
                fi
            done
        else
            log_warn "  Batch install failed, trying individually..."
            for pkg in $to_install; do
                if install_pkg "$pkg_manager" "$pkg" >/dev/null 2>&1; then
                    log_info "  [OK] $pkg"
                    ((installed_count++))
                else
                    log_warn "  [FAIL] $pkg (may not be in repos)"
                    ((failed_count++))
                fi
            done
        fi
    else
        log_info "All forensic tools already installed ($skipped_count packages)"
    fi

    # Install YARA if needed
    if ! has_tool yara; then
        log_info "Installing YARA..."
        if install_pkg "$pkg_manager" "yara" >/dev/null 2>&1 && has_tool yara; then
            log_info "  [OK] yara"
            ((installed_count++))
        else
            log_warn "  [SKIP] yara (not in repos, skipping source build in competition mode)"
            ((failed_count++))
        fi
    fi

    # Install Volatility 3 if memory analysis is requested
    if [[ "$ENABLE_VOLATILITY" == "true" ]] && ! has_tool vol3 && ! has_tool volatility3; then
        log_info "Installing Volatility 3..."
        case "$pkg_manager" in
            apt) timeout 30 apt-get install -y -qq python3 python3-pip python3-venv 2>&1 | tail -3 || true ;;
            dnf|yum) timeout 30 $pkg_manager install -y --setopt=timeout=15 python3 python3-pip 2>&1 | tail -3 || true ;;
        esac

        if has_tool pip3; then
            if timeout 120 pip3 install -q volatility3 2>&1 | tail -5; then
                log_info "  [OK] volatility3 (pip)"
                ((installed_count++))
            else
                log_warn "  [FAIL] volatility3 (pip install failed or timed out)"
                ((failed_count++))
            fi
        else
            log_warn "  [SKIP] volatility3 (pip3 not available)"
            ((failed_count++))
        fi
    fi

    # Install AVML for memory dumps if requested
    if [[ "$ENABLE_MEMORY_DUMP" == "true" ]] && ! has_tool avml; then
        log_info "Installing AVML (memory acquisition)..."
        local avml_url="https://github.com/microsoft/avml/releases/download/v0.14.0/avml"
        if timeout 30 curl -sSL "$avml_url" -o /usr/local/bin/avml 2>&1; then
            chmod +x /usr/local/bin/avml
            log_info "  [OK] avml"
            ((installed_count++))
        else
            log_warn "  [FAIL] avml (download failed or timed out)"
            ((failed_count++))
        fi
    fi

    # Additional analysis tools (batch, best-effort)
    log_info "Installing additional analysis tools..."
    case "$pkg_manager" in
        apt)
            install_pkg "$pkg_manager" "xxd" >/dev/null 2>&1 || true
            install_pkg "$pkg_manager" "foremost sleuthkit" >/dev/null 2>&1 || true
            ;;
        dnf|yum)
            install_pkg "$pkg_manager" "vim-common" >/dev/null 2>&1 || true
            install_pkg "$pkg_manager" "sleuthkit" >/dev/null 2>&1 || true
            ;;
    esac

    echo ""
    log_info "=== AUTO-INSTALL SUMMARY ==="
    log_info "  Installed: $installed_count"
    log_info "  Already present: $skipped_count"
    log_info "  Failed/unavailable: $failed_count"
    echo "[✓] Auto-install phase complete"
    echo ""
}

# Run auto-install if enabled
install_forensic_tools

# ==============================================================================
# INITIALIZATION
# ==============================================================================

mkdir -p "${COLLECTION_DIR}"/{system,volatile,memory,network,persistence,users,logs,files,containers,kernel,rootkit,timeline,analysis,yara}

# Initialize findings CSV
echo "SEVERITY|CATEGORY|TIMESTAMP|MESSAGE" > "${COLLECTION_DIR}/findings.csv"

# Create metadata
cat > "${COLLECTION_DIR}/metadata.json" << EOF
{
    "hostname": "${HOSTNAME}",
    "timestamp": "${TIMESTAMP}",
    "collection_time": "$(date -Iseconds)",
    "collector_version": "3.0",
    "options": {
        "memory_dump": ${ENABLE_MEMORY_DUMP},
        "volatility": ${ENABLE_VOLATILITY},
        "quick_mode": ${QUICK_MODE},
        "skip_logs": ${SKIP_LOGS}
    },
    "system": {
        "kernel": "$(uname -r)",
        "arch": "$(uname -m)",
        "os": "$(cat /etc/os-release 2>/dev/null | grep ^ID= | cut -d= -f2 | tr -d '\"')"
    },
    "running_as_root": $(check_root && echo true || echo false)
}
EOF

echo "========================================"
echo "COMPREHENSIVE FORENSIC COLLECTOR v3.0"
echo "========================================"
echo "Host: ${HOSTNAME}"
echo "Output: ${OUTPUT_DIR}"
echo "Time: $(date -Iseconds)"
echo "Memory Dump: ${ENABLE_MEMORY_DUMP}"
echo "Volatility: ${ENABLE_VOLATILITY}"
echo "========================================"
echo ""

START_TIME=$(date +%s)

# ==============================================================================
# PHASE 1: VOLATILE DATA (Highest Priority - Collect First)
# ==============================================================================

log_phase "PHASE 1: VOLATILE DATA COLLECTION"

# System time (critical for timeline correlation)
log_info "Collecting: system time and timezone"
{
    echo "=== System Time ==="
    date -Iseconds
    echo ""
    echo "=== Hardware Clock ==="
    hwclock --show 2>/dev/null || echo "hwclock not available"
    echo ""
    echo "=== Timezone ==="
    cat /etc/timezone 2>/dev/null || timedatectl 2>/dev/null || echo "unknown"
    echo ""
    echo "=== NTP Status ==="
    timedatectl status 2>/dev/null || ntpq -p 2>/dev/null || chronyc tracking 2>/dev/null || echo "NTP status unknown"
} > "${COLLECTION_DIR}/volatile/system_time.txt"

# Running processes (CRITICAL - most volatile)
log_info "Collecting: process list with full details"
ps auxwwf > "${COLLECTION_DIR}/volatile/ps_auxwwf.txt" 2>&1
ps -eo pid,ppid,user,uid,gid,stat,start,time,comm,args --sort=-start > "${COLLECTION_DIR}/volatile/ps_full.txt" 2>&1
pstree -panu > "${COLLECTION_DIR}/volatile/pstree.txt" 2>&1

# Process details from /proc
log_info "Collecting: detailed process information from /proc"
mkdir -p "${COLLECTION_DIR}/volatile/proc_details"
for pid in /proc/[0-9]*; do
    pid_num=$(basename "$pid")
    if [[ -d "$pid" ]]; then
        {
            echo "=== PID: $pid_num ==="
            echo "Cmdline: $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null)"
            echo "Exe: $(readlink -f "$pid/exe" 2>/dev/null)"
            echo "Cwd: $(readlink -f "$pid/cwd" 2>/dev/null)"
            echo "Status:"
            cat "$pid/status" 2>/dev/null | head -20
            echo ""
        } >> "${COLLECTION_DIR}/volatile/proc_details/processes.txt"
    fi
done

# Open files and network connections
log_info "Collecting: open files and sockets"
lsof -n -P > "${COLLECTION_DIR}/volatile/lsof_full.txt" 2>&1 &
LSOF_PID=$!

# Network connections (volatile)
log_info "Collecting: network connections"
ss -tulpan > "${COLLECTION_DIR}/volatile/ss_tulpan.txt" 2>&1
ss -xp > "${COLLECTION_DIR}/volatile/ss_unix.txt" 2>&1
netstat -tulpan > "${COLLECTION_DIR}/volatile/netstat_tulpan.txt" 2>&1
netstat -an > "${COLLECTION_DIR}/volatile/netstat_all.txt" 2>&1

# Network configuration
log_info "Collecting: network configuration"
ip addr > "${COLLECTION_DIR}/volatile/ip_addr.txt" 2>&1
ip route > "${COLLECTION_DIR}/volatile/ip_route.txt" 2>&1
ip neigh > "${COLLECTION_DIR}/volatile/ip_neigh.txt" 2>&1
ip link > "${COLLECTION_DIR}/volatile/ip_link.txt" 2>&1
cat /proc/net/arp > "${COLLECTION_DIR}/volatile/proc_net_arp.txt" 2>&1

# Loaded kernel modules
log_info "Collecting: kernel modules"
lsmod > "${COLLECTION_DIR}/volatile/lsmod.txt" 2>&1
cat /proc/modules > "${COLLECTION_DIR}/volatile/proc_modules.txt" 2>&1

# Mount points
log_info "Collecting: mount points"
mount > "${COLLECTION_DIR}/volatile/mount.txt" 2>&1
cat /proc/mounts > "${COLLECTION_DIR}/volatile/proc_mounts.txt" 2>&1
findmnt -l > "${COLLECTION_DIR}/volatile/findmnt.txt" 2>&1

# Memory info
log_info "Collecting: memory information"
cat /proc/meminfo > "${COLLECTION_DIR}/volatile/meminfo.txt"
cat /proc/vmstat > "${COLLECTION_DIR}/volatile/vmstat.txt"
free -h > "${COLLECTION_DIR}/volatile/free.txt" 2>&1

# System info
log_info "Collecting: system information"
uname -a > "${COLLECTION_DIR}/volatile/uname.txt"
uptime > "${COLLECTION_DIR}/volatile/uptime.txt"
cat /proc/version > "${COLLECTION_DIR}/volatile/proc_version.txt"
dmesg > "${COLLECTION_DIR}/volatile/dmesg.txt" 2>&1

# Wait for lsof
wait $LSOF_PID 2>/dev/null || true

echo "[✓] Phase 1 complete"

# ==============================================================================
# PHASE 2: MEMORY FORENSICS
# ==============================================================================

log_phase "PHASE 2: MEMORY FORENSICS"

# Process memory maps
log_info "Collecting: process memory maps"
for pid in /proc/[0-9]*; do
    pid_num=$(basename "$pid")
    if [[ -r "$pid/maps" ]]; then
        {
            echo "=== PID: $pid_num ($(cat "$pid/comm" 2>/dev/null)) ==="
            cat "$pid/maps" 2>/dev/null
            echo ""
        } >> "${COLLECTION_DIR}/memory/proc_maps.txt"
    fi
done

# Process memory statistics
log_info "Collecting: process memory statistics"
for pid in /proc/[0-9]*; do
    pid_num=$(basename "$pid")
    if [[ -r "$pid/smaps_rollup" ]]; then
        {
            echo "=== PID: $pid_num ==="
            cat "$pid/smaps_rollup" 2>/dev/null
            echo ""
        } >> "${COLLECTION_DIR}/memory/smaps_rollup.txt"
    fi
done

# Process environments (may contain credentials)
log_info "Collecting: process environments"
for pid in /proc/[0-9]*; do
    pid_num=$(basename "$pid")
    if [[ -r "$pid/environ" ]]; then
        {
            echo "=== PID: $pid_num ($(cat "$pid/comm" 2>/dev/null)) ==="
            tr '\0' '\n' < "$pid/environ" 2>/dev/null
            echo ""
        } >> "${COLLECTION_DIR}/memory/proc_environ.txt"
    fi
done

# Deleted files still in memory
log_info "Collecting: deleted files in memory"
find /proc/*/fd -type l 2>/dev/null | while read fd; do
    target=$(readlink "$fd" 2>/dev/null)
    if [[ "$target" == *"(deleted)"* ]]; then
        pid=$(echo "$fd" | cut -d/ -f3)
        echo "PID $pid: $fd -> $target"
    fi
done > "${COLLECTION_DIR}/memory/deleted_files.txt"

# Shared memory segments
log_info "Collecting: shared memory"
ipcs -m > "${COLLECTION_DIR}/memory/ipcs_shm.txt" 2>&1
ipcs -s > "${COLLECTION_DIR}/memory/ipcs_sem.txt" 2>&1
ipcs -q > "${COLLECTION_DIR}/memory/ipcs_msg.txt" 2>&1
ls -la /dev/shm/ > "${COLLECTION_DIR}/memory/dev_shm.txt" 2>&1

# Full memory dump (if enabled)
if [[ "$ENABLE_MEMORY_DUMP" == "true" ]] && check_root; then
    log_info "Attempting full memory dump..."
    MEMORY_SIZE=$(get_available_memory)

    if [[ $MEMORY_SIZE -gt $MAX_MEMORY_DUMP ]]; then
        log_warn "Memory size ($MEMORY_SIZE) exceeds limit, skipping full dump"
    else
        # Try AVML first (preferred - statically compiled)
        if has_tool avml; then
            log_info "Using AVML for memory dump"
            timeout $MEMORY_TIMEOUT avml "${COLLECTION_DIR}/memory/memory.lime" 2>&1 | tee "${COLLECTION_DIR}/memory/avml.log"
        # Try LiME
        elif [[ -f /proc/kallsyms ]] && has_tool insmod; then
            log_info "Attempting LiME memory dump"
            # Check for LiME module
            LIME_MODULE=$(find /lib/modules/$(uname -r) -name "lime*.ko" 2>/dev/null | head -1)
            if [[ -n "$LIME_MODULE" ]]; then
                insmod "$LIME_MODULE" "path=${COLLECTION_DIR}/memory/memory.lime format=lime" 2>&1 | tee "${COLLECTION_DIR}/memory/lime.log"
                rmmod lime 2>/dev/null || true
            else
                log_warn "LiME module not found"
            fi
        # Fallback to /proc/kcore (if readable)
        elif [[ -r /proc/kcore ]]; then
            log_info "Copying /proc/kcore (partial memory)"
            timeout $MEMORY_TIMEOUT dd if=/proc/kcore of="${COLLECTION_DIR}/memory/kcore.raw" bs=1M count=1024 2>&1 | tee "${COLLECTION_DIR}/memory/kcore.log" || true
        else
            log_warn "No memory dump method available"
        fi
    fi

    # Run Volatility analysis if enabled and memory dump exists
    if [[ "$ENABLE_VOLATILITY" == "true" ]] && has_tool vol3 || has_tool volatility3; then
        VOL_CMD=$(has_tool vol3 && echo "vol3" || echo "volatility3")
        MEMORY_FILE=$(find "${COLLECTION_DIR}/memory" -name "*.lime" -o -name "*.raw" 2>/dev/null | head -1)

        if [[ -n "$MEMORY_FILE" ]]; then
            log_info "Running Volatility 3 analysis..."
            mkdir -p "${COLLECTION_DIR}/analysis/volatility"

            # Run key Volatility plugins
            for plugin in linux.pslist linux.pstree linux.lsmod linux.bash linux.check_syscall linux.hidden_modules linux.malfind linux.sockstat; do
                log_info "Running: $plugin"
                timeout 600 $VOL_CMD -f "$MEMORY_FILE" $plugin > "${COLLECTION_DIR}/analysis/volatility/${plugin}.txt" 2>&1 || true
            done
        fi
    fi
fi

echo "[✓] Phase 2 complete"

# ==============================================================================
# PHASE 3: KERNEL ROOTKIT DETECTION
# ==============================================================================

log_phase "PHASE 3: KERNEL ROOTKIT DETECTION"

mkdir -p "${COLLECTION_DIR}/rootkit"

# Check for hidden kernel modules
log_info "Checking: hidden kernel modules"
{
    echo "=== Kernel Module Comparison ==="
    echo "Modules in /proc/modules:"
    cat /proc/modules | awk '{print $1}' | sort > /tmp/proc_modules.tmp
    echo ""
    echo "Modules from lsmod:"
    lsmod | tail -n +2 | awk '{print $1}' | sort > /tmp/lsmod_modules.tmp
    echo ""
    echo "Differences (potential hidden modules):"
    diff /tmp/proc_modules.tmp /tmp/lsmod_modules.tmp 2>&1 || echo "No differences"
    rm -f /tmp/proc_modules.tmp /tmp/lsmod_modules.tmp
} > "${COLLECTION_DIR}/rootkit/hidden_modules.txt"

# Check syscall table (if System.map available)
log_info "Checking: syscall table integrity"
{
    echo "=== Syscall Table Analysis ==="
    SYSTEM_MAP="/boot/System.map-$(uname -r)"
    if [[ -r "$SYSTEM_MAP" ]]; then
        echo "System.map found: $SYSTEM_MAP"
        echo ""
        echo "Syscall table address from System.map:"
        grep -E "sys_call_table|ia32_sys_call_table" "$SYSTEM_MAP"
        echo ""
        echo "Current syscall table (from /proc/kallsyms):"
        cat /proc/kallsyms 2>/dev/null | grep -E "sys_call_table|ia32_sys_call_table" || echo "Cannot read kallsyms"
    else
        echo "System.map not found - cannot verify syscall table"
    fi
} > "${COLLECTION_DIR}/rootkit/syscall_table.txt"

# Check for /proc anomalies
log_info "Checking: /proc anomalies"
{
    echo "=== /proc Anomaly Detection ==="
    echo ""
    echo "Processes visible in /proc:"
    ls -1d /proc/[0-9]* 2>/dev/null | wc -l
    echo ""
    echo "Processes from ps:"
    ps -e --no-headers | wc -l
    echo ""
    echo "Difference may indicate hidden processes"
    echo ""
    echo "Checking for unusual /proc entries:"
    find /proc -maxdepth 1 -type d 2>/dev/null | while read dir; do
        name=$(basename "$dir")
        if [[ "$name" =~ ^[0-9]+$ ]]; then
            # Check if process exists but has no cmdline (potential hiding)
            if [[ -d "$dir" ]] && [[ ! -s "$dir/cmdline" ]] && [[ -r "$dir/status" ]]; then
                echo "Suspicious: PID $name has empty cmdline"
                cat "$dir/status" 2>/dev/null | head -5
                echo ""
            fi
        fi
    done
} > "${COLLECTION_DIR}/rootkit/proc_anomalies.txt"

# Check for kernel symbol hiding
log_info "Checking: kernel symbol anomalies"
{
    echo "=== Kernel Symbol Analysis ==="
    if [[ -r /proc/kallsyms ]]; then
        echo "Total kernel symbols:"
        wc -l < /proc/kallsyms
        echo ""
        echo "Checking for hooked functions (common targets):"
        for func in sys_read sys_write sys_open sys_close sys_execve sys_fork sys_clone tcp4_seq_show; do
            echo -n "$func: "
            grep -w "$func" /proc/kallsyms | head -1 || echo "NOT FOUND (suspicious)"
        done
    else
        echo "Cannot read /proc/kallsyms"
    fi
} > "${COLLECTION_DIR}/rootkit/kernel_symbols.txt"

# Check for LD_PRELOAD and library injection
log_info "Checking: library injection vectors"
{
    echo "=== Library Injection Check ==="
    echo ""
    echo "=== /etc/ld.so.preload ==="
    if [[ -f /etc/ld.so.preload ]]; then
        echo "WARNING: /etc/ld.so.preload EXISTS!"
        log_finding "CRITICAL" "rootkit" "ld.so.preload exists - potential rootkit"
        cat /etc/ld.so.preload
    else
        echo "Not present (normal)"
    fi
    echo ""
    echo "=== LD_PRELOAD in process environments ==="
    grep -r "LD_PRELOAD" /proc/*/environ 2>/dev/null | while read line; do
        pid=$(echo "$line" | cut -d/ -f3)
        echo "PID $pid: $(cat /proc/$pid/comm 2>/dev/null) has LD_PRELOAD set"
        log_finding "HIGH" "injection" "Process $pid has LD_PRELOAD set"
    done || echo "None found"
    echo ""
    echo "=== /etc/ld.so.conf.d/ contents ==="
    ls -la /etc/ld.so.conf.d/ 2>/dev/null
    echo ""
    cat /etc/ld.so.conf.d/* 2>/dev/null
} > "${COLLECTION_DIR}/rootkit/library_injection.txt"

# Check for network hiding (comparing ss with /proc/net)
log_info "Checking: hidden network connections"
{
    echo "=== Network Connection Comparison ==="
    echo ""
    echo "Connections from ss:"
    ss -tulpan | grep LISTEN | wc -l
    echo ""
    echo "Connections from /proc/net/tcp:"
    tail -n +2 /proc/net/tcp | wc -l
    echo ""
    echo "Detailed /proc/net/tcp:"
    cat /proc/net/tcp
    echo ""
    echo "Checking for port hiding (common backdoor ports):"
    for port in 4444 4445 4446 5555 6666 1337 31337 12345 65535; do
        hex_port=$(printf '%04X' $port)
        if grep -q ":${hex_port}" /proc/net/tcp 2>/dev/null; then
            if ! ss -tlnp | grep -q ":$port"; then
                echo "SUSPICIOUS: Port $port in /proc/net/tcp but not in ss output!"
                log_finding "HIGH" "rootkit" "Hidden network port: $port"
            fi
        fi
    done
} > "${COLLECTION_DIR}/rootkit/hidden_network.txt"

# Check interrupt handlers
log_info "Checking: interrupt handlers"
cat /proc/interrupts > "${COLLECTION_DIR}/rootkit/interrupts.txt" 2>&1

# Check kernel config
log_info "Checking: kernel security config"
{
    echo "=== Kernel Security Configuration ==="
    echo ""
    echo "Kernel command line:"
    cat /proc/cmdline
    echo ""
    echo "Security modules:"
    cat /sys/kernel/security/lsm 2>/dev/null || echo "Cannot read LSM"
    echo ""
    echo "ASLR status:"
    cat /proc/sys/kernel/randomize_va_space
    echo ""
    echo "Kernel pointers hidden:"
    cat /proc/sys/kernel/kptr_restrict
    echo ""
    echo "dmesg restrictions:"
    cat /proc/sys/kernel/dmesg_restrict
} > "${COLLECTION_DIR}/rootkit/kernel_security.txt"

# Rkhunter/chkrootkit if available
if has_tool rkhunter && [[ "$QUICK_MODE" != "true" ]]; then
    log_info "Running: rkhunter"
    timeout 600 rkhunter --check --skip-keypress --report-warnings-only > "${COLLECTION_DIR}/rootkit/rkhunter.txt" 2>&1 || true
fi

if has_tool chkrootkit && [[ "$QUICK_MODE" != "true" ]]; then
    log_info "Running: chkrootkit"
    timeout 600 chkrootkit > "${COLLECTION_DIR}/rootkit/chkrootkit.txt" 2>&1 || true
fi

echo "[✓] Phase 3 complete"

# ==============================================================================
# PHASE 4: HIDDEN PROCESS DETECTION
# ==============================================================================

log_phase "PHASE 4: HIDDEN PROCESS DETECTION"

{
    echo "=== Hidden Process Detection ==="
    echo ""

    # Method 1: Compare /proc with ps output
    echo "Method 1: /proc vs ps comparison"
    echo "PIDs in /proc:"
    PROC_PIDS=$(ls -1d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n)
    echo "$PROC_PIDS" > /tmp/proc_pids.tmp

    echo "PIDs from ps:"
    PS_PIDS=$(ps -e --no-headers -o pid | tr -d ' ' | sort -n)
    echo "$PS_PIDS" > /tmp/ps_pids.tmp

    echo ""
    echo "PIDs in /proc but not in ps (potentially hidden):"
    comm -23 /tmp/proc_pids.tmp /tmp/ps_pids.tmp

    echo ""
    echo "PIDs in ps but not in /proc (zombie/race condition):"
    comm -13 /tmp/proc_pids.tmp /tmp/ps_pids.tmp

    rm -f /tmp/proc_pids.tmp /tmp/ps_pids.tmp

    # Method 2: Check for processes with mismatched exe and cmdline
    echo ""
    echo "Method 2: exe/cmdline mismatch detection"
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        exe=$(readlink "$pid/exe" 2>/dev/null)
        cmdline=$(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null)

        if [[ -n "$exe" ]] && [[ -n "$cmdline" ]]; then
            exe_base=$(basename "$exe" 2>/dev/null)
            cmdline_base=$(echo "$cmdline" | awk '{print $1}' | xargs basename 2>/dev/null)

            # Check for name mismatch (common evasion technique)
            if [[ "$exe_base" != "$cmdline_base" ]] && [[ "$exe" != *"(deleted)"* ]]; then
                echo "Mismatch PID $pid_num: exe=$exe cmdline=$cmdline"
            fi
        fi

        # Check for deleted executables still running
        if [[ "$exe" == *"(deleted)"* ]]; then
            echo "Deleted exe PID $pid_num: $exe"
            log_finding "HIGH" "process" "Process $pid_num running from deleted executable: $exe"
        fi
    done

    # Method 3: Thread group analysis
    echo ""
    echo "Method 3: Orphaned threads"
    for pid in /proc/[0-9]*; do
        if [[ -d "$pid/task" ]]; then
            main_pid=$(basename "$pid")
            for tid in "$pid/task"/*; do
                tid_num=$(basename "$tid")
                if [[ "$tid_num" != "$main_pid" ]]; then
                    tgid=$(awk '/Tgid/ {print $2}' "$tid/status" 2>/dev/null)
                    if [[ "$tgid" != "$main_pid" ]]; then
                        echo "Orphaned thread: TID $tid_num (TGID mismatch: expected $main_pid, got $tgid)"
                    fi
                fi
            done
        fi
    done

} > "${COLLECTION_DIR}/rootkit/hidden_processes.txt"

echo "[✓] Phase 4 complete"

# ==============================================================================
# PHASE 5: PERSISTENCE MECHANISMS
# ==============================================================================

log_phase "PHASE 5: PERSISTENCE MECHANISMS"

# Cron jobs
log_info "Collecting: cron jobs"
mkdir -p "${COLLECTION_DIR}/persistence/cron"
crontab -l > "${COLLECTION_DIR}/persistence/cron/root_crontab.txt" 2>&1 || true
cp /etc/crontab "${COLLECTION_DIR}/persistence/cron/etc_crontab" 2>/dev/null || true
cp -r /etc/cron.d "${COLLECTION_DIR}/persistence/cron/" 2>/dev/null || true
cp -r /etc/cron.daily "${COLLECTION_DIR}/persistence/cron/" 2>/dev/null || true
cp -r /etc/cron.hourly "${COLLECTION_DIR}/persistence/cron/" 2>/dev/null || true
cp -r /etc/cron.weekly "${COLLECTION_DIR}/persistence/cron/" 2>/dev/null || true
cp -r /etc/cron.monthly "${COLLECTION_DIR}/persistence/cron/" 2>/dev/null || true

# User crontabs
{
    echo "=== User Crontabs ==="
    for user_home in /home/* /root; do
        username=$(basename "$user_home")
        if crontab -l -u "$username" 2>/dev/null; then
            echo "=== $username ==="
            crontab -l -u "$username"
            echo ""
        fi
    done
} > "${COLLECTION_DIR}/persistence/cron/user_crontabs.txt" 2>&1

# Systemd
log_info "Collecting: systemd services"
mkdir -p "${COLLECTION_DIR}/persistence/systemd"
systemctl list-unit-files --type=service > "${COLLECTION_DIR}/persistence/systemd/unit_files.txt" 2>&1
systemctl list-units --type=service --all > "${COLLECTION_DIR}/persistence/systemd/all_units.txt" 2>&1
systemctl list-timers --all > "${COLLECTION_DIR}/persistence/systemd/timers.txt" 2>&1

# Copy custom service files
for dir in /etc/systemd/system /usr/local/lib/systemd/system ~/.config/systemd/user; do
    if [[ -d "$dir" ]]; then
        cp -r "$dir" "${COLLECTION_DIR}/persistence/systemd/$(basename $dir)_custom" 2>/dev/null || true
    fi
done

# Init scripts
log_info "Collecting: init scripts"
cp -r /etc/init.d "${COLLECTION_DIR}/persistence/" 2>/dev/null || true
cp /etc/rc.local "${COLLECTION_DIR}/persistence/rc.local" 2>/dev/null || true

# AT jobs
log_info "Collecting: at jobs"
atq > "${COLLECTION_DIR}/persistence/atjobs.txt" 2>&1 || true

# SSH authorized keys (persistence vector)
log_info "Collecting: SSH authorized keys"
mkdir -p "${COLLECTION_DIR}/persistence/ssh_keys"
{
    for user_home in /home/* /root; do
        username=$(basename "$user_home")
        auth_keys="$user_home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            echo "=== $username: $auth_keys ==="
            cat "$auth_keys"
            echo ""
            cp "$auth_keys" "${COLLECTION_DIR}/persistence/ssh_keys/${username}_authorized_keys" 2>/dev/null || true
        fi
    done
} > "${COLLECTION_DIR}/persistence/ssh_keys/all_keys.txt"

# Sudoers
log_info "Collecting: sudoers configuration"
cp /etc/sudoers "${COLLECTION_DIR}/persistence/sudoers" 2>/dev/null || true
cp -r /etc/sudoers.d "${COLLECTION_DIR}/persistence/" 2>/dev/null || true

# Shell profiles (persistence vector)
log_info "Collecting: shell profiles"
mkdir -p "${COLLECTION_DIR}/persistence/shell_profiles"
cp /etc/profile "${COLLECTION_DIR}/persistence/shell_profiles/etc_profile" 2>/dev/null || true
cp /etc/bash.bashrc "${COLLECTION_DIR}/persistence/shell_profiles/etc_bash.bashrc" 2>/dev/null || true
cp -r /etc/profile.d "${COLLECTION_DIR}/persistence/shell_profiles/" 2>/dev/null || true

for user_home in /home/* /root; do
    username=$(basename "$user_home")
    for profile in .profile .bashrc .bash_profile .zshrc .zprofile; do
        if [[ -f "$user_home/$profile" ]]; then
            cp "$user_home/$profile" "${COLLECTION_DIR}/persistence/shell_profiles/${username}_${profile}" 2>/dev/null || true
        fi
    done
done

# ld.so.preload (rootkit persistence)
log_info "Collecting: ld.so.preload"
if [[ -f /etc/ld.so.preload ]]; then
    cp /etc/ld.so.preload "${COLLECTION_DIR}/persistence/ld.so.preload"
    log_finding "CRITICAL" "persistence" "ld.so.preload exists"
else
    echo "Not present" > "${COLLECTION_DIR}/persistence/ld.so.preload"
fi

# PAM configuration
log_info "Collecting: PAM configuration"
cp -r /etc/pam.d "${COLLECTION_DIR}/persistence/" 2>/dev/null || true

# Kernel modules autoload
log_info "Collecting: kernel module autoload"
cp /etc/modules "${COLLECTION_DIR}/persistence/modules" 2>/dev/null || true
cp -r /etc/modules-load.d "${COLLECTION_DIR}/persistence/" 2>/dev/null || true
cp -r /etc/modprobe.d "${COLLECTION_DIR}/persistence/" 2>/dev/null || true

echo "[✓] Phase 5 complete"

# ==============================================================================
# PHASE 6: USER ACCOUNTS
# ==============================================================================

log_phase "PHASE 6: USER ACCOUNT ANALYSIS"

mkdir -p "${COLLECTION_DIR}/users"

# Core user files
cp /etc/passwd "${COLLECTION_DIR}/users/passwd"
cp /etc/shadow "${COLLECTION_DIR}/users/shadow" 2>/dev/null || true
cp /etc/group "${COLLECTION_DIR}/users/group"
cp /etc/gshadow "${COLLECTION_DIR}/users/gshadow" 2>/dev/null || true

# Analyze users
{
    echo "=== User Account Analysis ==="
    echo ""
    echo "=== UID 0 Users (should only be root) ==="
    awk -F: '$3 == 0 {print $1}' /etc/passwd

    uid0_count=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        log_finding "CRITICAL" "users" "Multiple UID 0 users detected: $uid0_count"
    fi

    echo ""
    echo "=== Users with login shells ==="
    grep -v "nologin\|false" /etc/passwd | awk -F: '{print $1 ":" $7}'

    echo ""
    echo "=== Recently created users (UID >= 1000) ==="
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1 ":" $3 ":" $6}' /etc/passwd

    echo ""
    echo "=== Users with empty passwords ==="
    if [[ -r /etc/shadow ]]; then
        awk -F: '$2 == "" {print $1}' /etc/shadow
        empty_pass=$(awk -F: '$2 == ""' /etc/shadow | wc -l)
        if [[ $empty_pass -gt 0 ]]; then
            log_finding "CRITICAL" "auth" "Users with empty passwords: $empty_pass"
        fi
    fi

    echo ""
    echo "=== Sudo group members ==="
    grep -E "^(sudo|wheel):" /etc/group

} > "${COLLECTION_DIR}/users/user_analysis.txt"

# Login history
log_info "Collecting: login history"
last -Faixw > "${COLLECTION_DIR}/users/last.txt" 2>&1 || last > "${COLLECTION_DIR}/users/last.txt" 2>&1
lastb > "${COLLECTION_DIR}/users/lastb.txt" 2>&1 || true
lastlog > "${COLLECTION_DIR}/users/lastlog.txt" 2>&1 || true
who > "${COLLECTION_DIR}/users/who.txt" 2>&1
w > "${COLLECTION_DIR}/users/w.txt" 2>&1

# Shell histories
log_info "Collecting: shell histories"
mkdir -p "${COLLECTION_DIR}/users/histories"
for user_home in /home/* /root; do
    username=$(basename "$user_home")
    for hist in .bash_history .zsh_history .history; do
        if [[ -f "$user_home/$hist" ]]; then
            tail -10000 "$user_home/$hist" > "${COLLECTION_DIR}/users/histories/${username}_${hist}" 2>/dev/null || true
        fi
    done
done

echo "[✓] Phase 6 complete"

# ==============================================================================
# PHASE 7: NETWORK FORENSICS
# ==============================================================================

log_phase "PHASE 7: NETWORK FORENSICS"

mkdir -p "${COLLECTION_DIR}/network"

# Firewall rules
log_info "Collecting: firewall rules"
iptables -L -n -v > "${COLLECTION_DIR}/network/iptables.txt" 2>&1 || true
iptables -t nat -L -n -v > "${COLLECTION_DIR}/network/iptables_nat.txt" 2>&1 || true
ip6tables -L -n -v > "${COLLECTION_DIR}/network/ip6tables.txt" 2>&1 || true
nft list ruleset > "${COLLECTION_DIR}/network/nftables.txt" 2>&1 || true
ufw status verbose > "${COLLECTION_DIR}/network/ufw.txt" 2>&1 || true
firewall-cmd --list-all > "${COLLECTION_DIR}/network/firewalld.txt" 2>&1 || true

# DNS configuration
log_info "Collecting: DNS configuration"
cp /etc/resolv.conf "${COLLECTION_DIR}/network/resolv.conf" 2>/dev/null || true
cp /etc/hosts "${COLLECTION_DIR}/network/hosts" 2>/dev/null || true
cp /etc/nsswitch.conf "${COLLECTION_DIR}/network/nsswitch.conf" 2>/dev/null || true

# Network namespaces
log_info "Collecting: network namespaces"
{
    echo "=== Network Namespaces ==="
    ip netns list 2>/dev/null
    echo ""
    echo "=== Namespace Details ==="
    for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
        echo "--- Namespace: $ns ---"
        ip netns exec "$ns" ip addr 2>/dev/null
        ip netns exec "$ns" ss -tulpan 2>/dev/null
        echo ""
    done
} > "${COLLECTION_DIR}/network/namespaces.txt"

# Established connections analysis
log_info "Analyzing: suspicious connections"
{
    echo "=== Suspicious Connection Analysis ==="
    echo ""
    echo "=== Connections to known bad ports ==="
    for port in 4444 4445 4446 5555 6666 1337 31337 12345 23; do
        ss -tulpan | grep ":$port" && log_finding "HIGH" "network" "Connection on suspicious port $port"
    done
    echo ""
    echo "=== External connections (non-RFC1918) ==="
    ss -tulpan | grep -v "127.0.0.1\|::1\|10\.\|172\.1[6-9]\.\|172\.2[0-9]\.\|172\.3[0-1]\.\|192\.168\." | grep ESTAB || true
} > "${COLLECTION_DIR}/network/suspicious_connections.txt" 2>&1

echo "[✓] Phase 7 complete"

# ==============================================================================
# PHASE 8: CONTAINER FORENSICS
# ==============================================================================

log_phase "PHASE 8: CONTAINER FORENSICS"

mkdir -p "${COLLECTION_DIR}/containers"

# Docker
if has_tool docker; then
    log_info "Collecting: Docker information"
    docker info > "${COLLECTION_DIR}/containers/docker_info.txt" 2>&1 || true
    docker ps -a > "${COLLECTION_DIR}/containers/docker_ps.txt" 2>&1 || true
    docker images > "${COLLECTION_DIR}/containers/docker_images.txt" 2>&1 || true
    docker network ls > "${COLLECTION_DIR}/containers/docker_networks.txt" 2>&1 || true
    docker volume ls > "${COLLECTION_DIR}/containers/docker_volumes.txt" 2>&1 || true

    # Inspect running containers
    for container in $(docker ps -q 2>/dev/null); do
        docker inspect "$container" > "${COLLECTION_DIR}/containers/docker_inspect_${container}.json" 2>&1 || true
    done
fi

# Podman
if has_tool podman; then
    log_info "Collecting: Podman information"
    podman info > "${COLLECTION_DIR}/containers/podman_info.txt" 2>&1 || true
    podman ps -a > "${COLLECTION_DIR}/containers/podman_ps.txt" 2>&1 || true
    podman images > "${COLLECTION_DIR}/containers/podman_images.txt" 2>&1 || true
fi

# Kubernetes
if has_tool kubectl; then
    log_info "Collecting: Kubernetes information"
    kubectl get pods --all-namespaces > "${COLLECTION_DIR}/containers/k8s_pods.txt" 2>&1 || true
    kubectl get services --all-namespaces > "${COLLECTION_DIR}/containers/k8s_services.txt" 2>&1 || true
    kubectl get secrets --all-namespaces -o yaml > "${COLLECTION_DIR}/containers/k8s_secrets.txt" 2>&1 || true
fi

# Container escape indicators
log_info "Checking: container escape indicators"
{
    echo "=== Container Environment Detection ==="
    echo ""
    if [[ -f /.dockerenv ]]; then
        echo "Running inside Docker container"
    fi
    if grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
        echo "Containerized environment detected in cgroup"
    fi
    echo ""
    echo "=== Checking for privileged container indicators ==="
    if [[ -w /dev/sda ]]; then
        echo "WARNING: Raw disk device writable - potentially privileged container"
        log_finding "HIGH" "container" "Privileged container detected - raw disk access"
    fi
    if capsh --print 2>/dev/null | grep -q "cap_sys_admin"; then
        echo "WARNING: CAP_SYS_ADMIN capability present"
    fi
} > "${COLLECTION_DIR}/containers/escape_indicators.txt"

echo "[✓] Phase 8 complete"

# ==============================================================================
# PHASE 9: FILE SYSTEM ANALYSIS
# ==============================================================================

log_phase "PHASE 9: FILE SYSTEM ANALYSIS"

mkdir -p "${COLLECTION_DIR}/files"

# SUID/SGID binaries
log_info "Collecting: SUID/SGID binaries"
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -500 > "${COLLECTION_DIR}/files/suid_sgid_all.txt"

# Non-standard SUID
{
    echo "=== Non-standard SUID/SGID binaries ==="
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read file; do
        # Skip standard locations
        if [[ ! "$file" =~ ^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/ ]]; then
            ls -la "$file"
            log_finding "MEDIUM" "files" "Non-standard SUID/SGID: $file"
        fi
    done
} > "${COLLECTION_DIR}/files/suid_nonstandard.txt"

# World-writable files in system dirs
log_info "Collecting: world-writable system files"
find /etc /usr /bin /sbin /lib -type f -perm -0002 2>/dev/null | head -100 > "${COLLECTION_DIR}/files/world_writable.txt"

# Hidden files in suspicious locations
log_info "Collecting: hidden files in suspicious locations"
{
    echo "=== Hidden files in /tmp ==="
    find /tmp -name ".*" -type f 2>/dev/null
    echo ""
    echo "=== Hidden files in /var/tmp ==="
    find /var/tmp -name ".*" -type f 2>/dev/null
    echo ""
    echo "=== Hidden files in /dev/shm ==="
    find /dev/shm -name ".*" -type f 2>/dev/null
    echo ""
    echo "=== Files in /dev/shm ==="
    ls -la /dev/shm/
} > "${COLLECTION_DIR}/files/hidden_files.txt"

# Recently modified system files
log_info "Collecting: recently modified system files"
find /etc /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null | head -200 > "${COLLECTION_DIR}/files/recently_modified.txt"

# Suspicious file extensions
log_info "Collecting: suspicious file extensions"
{
    echo "=== Suspicious file extensions ==="
    find /tmp /var/tmp /dev/shm /home -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.elf" \) 2>/dev/null | head -100
} > "${COLLECTION_DIR}/files/suspicious_extensions.txt"

echo "[✓] Phase 9 complete"

# ==============================================================================
# PHASE 10: FILE HASHING
# ==============================================================================

if [[ "$QUICK_MODE" != "true" ]]; then
    log_phase "PHASE 10: FILE HASHING"

    mkdir -p "${COLLECTION_DIR}/hashes"

    log_info "Hashing: critical binaries"
    for dir in /bin /sbin /usr/bin /usr/sbin; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f -executable 2>/dev/null | head -500 | while read f; do
                sha256sum "$f" 2>/dev/null
            done
        fi
    done > "${COLLECTION_DIR}/hashes/binaries.sha256"

    log_info "Hashing: libraries"
    find /lib /lib64 /usr/lib /usr/lib64 -name "*.so*" -type f 2>/dev/null | head -500 | while read f; do
        sha256sum "$f" 2>/dev/null
    done > "${COLLECTION_DIR}/hashes/libraries.sha256"

    log_info "Hashing: config files"
    find /etc -type f -size -1M 2>/dev/null | head -200 | while read f; do
        sha256sum "$f" 2>/dev/null
    done > "${COLLECTION_DIR}/hashes/configs.sha256"

    echo "[✓] Phase 10 complete"
fi

# ==============================================================================
# PHASE 11: TIMELINE GENERATION
# ==============================================================================

if [[ "$QUICK_MODE" != "true" ]]; then
    log_phase "PHASE 11: TIMELINE GENERATION"

    mkdir -p "${COLLECTION_DIR}/timeline"

    log_info "Generating: bodyfile for critical directories"

    # Generate bodyfile format (TSK compatible)
    {
        for dir in /etc /var/log /tmp /home /root /bin /sbin /usr/bin /usr/sbin; do
            if [[ -d "$dir" ]]; then
                find "$dir" -maxdepth 3 -printf "%m|%u|%g|%s|%A@|%T@|%C@|%p\n" 2>/dev/null
            fi
        done
    } > "${COLLECTION_DIR}/timeline/bodyfile.txt"

    # Create mactime-compatible format
    log_info "Converting: to mactime format"
    {
        echo "Date,Size,Type,Mode,UID,GID,Meta,File Name"
        while IFS='|' read mode user group size atime mtime ctime path; do
            # Convert to readable format
            atime_fmt=$(date -d "@${atime%.*}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")
            mtime_fmt=$(date -d "@${mtime%.*}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")
            ctime_fmt=$(date -d "@${ctime%.*}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")

            echo "m|$mtime_fmt|$size|f|$mode|$user|$group|0|$path"
            echo "a|$atime_fmt|$size|f|$mode|$user|$group|0|$path"
            echo "c|$ctime_fmt|$size|f|$mode|$user|$group|0|$path"
        done < "${COLLECTION_DIR}/timeline/bodyfile.txt"
    } > "${COLLECTION_DIR}/timeline/mactime.csv" 2>/dev/null

    echo "[✓] Phase 11 complete"
fi

# ==============================================================================
# PHASE 12: LOG COLLECTION
# ==============================================================================

if [[ "$SKIP_LOGS" != "true" ]]; then
    log_phase "PHASE 12: LOG COLLECTION"

    mkdir -p "${COLLECTION_DIR}/logs"

    # Auth logs
    log_info "Collecting: authentication logs"
    for log in /var/log/auth.log /var/log/secure /var/log/audit/audit.log; do
        if [[ -f "$log" ]]; then
            tail -c $MAX_LOG_SIZE "$log" > "${COLLECTION_DIR}/logs/$(basename $log)" 2>/dev/null
        fi
    done

    # System logs
    log_info "Collecting: system logs"
    for log in /var/log/syslog /var/log/messages /var/log/kern.log /var/log/dmesg; do
        if [[ -f "$log" ]]; then
            tail -c $MAX_LOG_SIZE "$log" > "${COLLECTION_DIR}/logs/$(basename $log)" 2>/dev/null
        fi
    done

    # Journal
    log_info "Collecting: systemd journal"
    journalctl -n 50000 --no-pager > "${COLLECTION_DIR}/logs/journal.txt" 2>&1 || true
    journalctl -n 10000 -p err --no-pager > "${COLLECTION_DIR}/logs/journal_errors.txt" 2>&1 || true

    # Application logs
    log_info "Collecting: application logs"
    for log in /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log /var/log/nginx/error.log /var/log/mysql/error.log /var/log/postgresql/*.log; do
        if [[ -f "$log" ]]; then
            tail -c $MAX_LOG_SIZE "$log" > "${COLLECTION_DIR}/logs/$(basename $log)" 2>/dev/null
        fi
    done

    # Audit logs
    if [[ -d /var/log/audit ]]; then
        cp -r /var/log/audit "${COLLECTION_DIR}/logs/" 2>/dev/null || true
    fi

    echo "[✓] Phase 12 complete"
fi

# ==============================================================================
# PHASE 13: YARA SCANNING
# ==============================================================================

if has_tool yara && [[ "$QUICK_MODE" != "true" ]]; then
    log_phase "PHASE 13: YARA SCANNING"

    mkdir -p "${COLLECTION_DIR}/yara"

    # Check for YARA rules
    YARA_RULES=""
    for rules_path in /etc/yara/rules /opt/yara/rules /usr/share/yara /var/lib/yara; do
        if [[ -d "$rules_path" ]]; then
            YARA_RULES="$rules_path"
            break
        fi
    done

    if [[ -n "$YARA_RULES" ]]; then
        log_info "Running YARA scan with rules from: $YARA_RULES"

        # Scan suspicious locations
        for scan_dir in /tmp /var/tmp /dev/shm /home; do
            if [[ -d "$scan_dir" ]]; then
                log_info "Scanning: $scan_dir"
                find "$scan_dir" -type f -size -10M 2>/dev/null | while read file; do
                    yara -r "$YARA_RULES"/*.yar "$file" 2>/dev/null
                done >> "${COLLECTION_DIR}/yara/matches.txt"
            fi
        done

        # Scan running processes
        log_info "Scanning: process memory"
        for pid in /proc/[0-9]*; do
            pid_num=$(basename "$pid")
            if [[ -r "$pid/exe" ]]; then
                exe=$(readlink "$pid/exe" 2>/dev/null)
                if [[ -f "$exe" ]]; then
                    yara -r "$YARA_RULES"/*.yar "$exe" 2>/dev/null | while read match; do
                        echo "PID $pid_num ($exe): $match"
                    done >> "${COLLECTION_DIR}/yara/process_matches.txt"
                fi
            fi
        done
    else
        echo "No YARA rules found" > "${COLLECTION_DIR}/yara/status.txt"
    fi

    echo "[✓] Phase 13 complete"
fi

# ==============================================================================
# PHASE 14: ANALYSIS SUMMARY
# ==============================================================================

log_phase "PHASE 14: ANALYSIS SUMMARY"

{
    echo "========================================"
    echo "FORENSIC ANALYSIS SUMMARY"
    echo "========================================"
    echo ""
    echo "Collection Time: $(date -Iseconds)"
    echo "Host: ${HOSTNAME}"
    echo ""
    echo "=== CRITICAL FINDINGS ==="
    grep "^CRITICAL" "${COLLECTION_DIR}/findings.csv" 2>/dev/null | wc -l
    grep "^CRITICAL" "${COLLECTION_DIR}/findings.csv" 2>/dev/null || echo "None"
    echo ""
    echo "=== HIGH SEVERITY FINDINGS ==="
    grep "^HIGH" "${COLLECTION_DIR}/findings.csv" 2>/dev/null | wc -l
    grep "^HIGH" "${COLLECTION_DIR}/findings.csv" 2>/dev/null || echo "None"
    echo ""
    echo "=== MEDIUM SEVERITY FINDINGS ==="
    grep "^MEDIUM" "${COLLECTION_DIR}/findings.csv" 2>/dev/null | wc -l
    echo ""
    echo "=== COLLECTION STATISTICS ==="
    echo "Total files collected: $(find "${COLLECTION_DIR}" -type f | wc -l)"
    echo "Total size: $(du -sh "${COLLECTION_DIR}" | cut -f1)"
    echo ""
    echo "=== PHASES COMPLETED ==="
    echo "1. Volatile Data Collection"
    echo "2. Memory Forensics"
    echo "3. Kernel Rootkit Detection"
    echo "4. Hidden Process Detection"
    echo "5. Persistence Mechanisms"
    echo "6. User Account Analysis"
    echo "7. Network Forensics"
    echo "8. Container Forensics"
    echo "9. File System Analysis"
    [[ "$QUICK_MODE" != "true" ]] && echo "10. File Hashing"
    [[ "$QUICK_MODE" != "true" ]] && echo "11. Timeline Generation"
    [[ "$SKIP_LOGS" != "true" ]] && echo "12. Log Collection"
    has_tool yara && [[ "$QUICK_MODE" != "true" ]] && echo "13. YARA Scanning"
    echo "14. Analysis Summary"

} > "${COLLECTION_DIR}/analysis/summary.txt"

# Copy findings to analysis dir
cp "${COLLECTION_DIR}/findings.csv" "${COLLECTION_DIR}/analysis/" 2>/dev/null || true

echo "[✓] Phase 14 complete"

# ==============================================================================
# FINALIZATION
# ==============================================================================

log_phase "FINALIZING COLLECTION"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Update metadata with completion info
cat > "${COLLECTION_DIR}/metadata_final.json" << EOF
{
    "hostname": "${HOSTNAME}",
    "timestamp": "${TIMESTAMP}",
    "collection_start": "$(date -d @$START_TIME -Iseconds)",
    "collection_end": "$(date -Iseconds)",
    "duration_seconds": ${DURATION},
    "findings": {
        "critical": $(grep -c "^CRITICAL" "${COLLECTION_DIR}/findings.csv" 2>/dev/null || echo 0),
        "high": $(grep -c "^HIGH" "${COLLECTION_DIR}/findings.csv" 2>/dev/null || echo 0),
        "medium": $(grep -c "^MEDIUM" "${COLLECTION_DIR}/findings.csv" 2>/dev/null || echo 0)
    }
}
EOF

# Create tarball
log_info "Creating tarball: ${TARBALL}"
cd "${OUTPUT_DIR}"
tar -czf "${TARBALL}" "$(basename ${COLLECTION_DIR})"
chmod 600 "${TARBALL}"

# Cleanup collection directory
rm -rf "${COLLECTION_DIR}"

TARBALL_SIZE=$(stat -c%s "${TARBALL}" 2>/dev/null || stat -f%z "${TARBALL}" 2>/dev/null || echo "unknown")

echo ""
echo "========================================"
echo "COLLECTION COMPLETE"
echo "========================================"
echo "Host: ${HOSTNAME}"
echo "Duration: ${DURATION} seconds"
echo "Output: ${TARBALL}"
echo "Size: ${TARBALL_SIZE} bytes"
echo "========================================"
echo "TARBALL_PATH:${TARBALL}"
