#!/bin/bash
# ==============================================================================
# Analyze Forensic Artifacts - Security Analysis Script
# Parses collected forensic artifacts and flags suspicious findings
#
# Usage:
#   ./analyze_artifacts.sh <tarball_path>
#   ./analyze_artifacts.sh /tmp/forensics_*/hostname_forensics_*.tar.gz
#   ./analyze_artifacts.sh <tarball_path> --json    # Output as JSON
#
# Output:
#   Categorized findings (CRITICAL, WARNING, INFO)
# ==============================================================================

set -uo pipefail

# Colors (disabled for JSON output)
JSON_OUTPUT=false
if [ "${2:-}" = "--json" ]; then
    JSON_OUTPUT=true
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
fi

CRITICAL="${RED}[!] CRITICAL:${NC}"
WARNING="${YELLOW}[!] WARNING:${NC}"
INFO="${CYAN}[*] INFO:${NC}"

TARBALL="${1:-}"

if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
    echo "Usage: $0 <forensics_tarball.tar.gz> [--json]"
    exit 1
fi

# Create temp directory for extraction
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Extract tarball
tar -xzf "$TARBALL" -C "$TMPDIR" 2>/dev/null

# Find the extracted directory
EXTRACT_DIR=$(find "$TMPDIR" -maxdepth 1 -type d -name "*_forensics_*" | head -1)

if [ -z "$EXTRACT_DIR" ]; then
    echo "Error: Failed to extract tarball"
    exit 1
fi

# JSON output array
declare -a FINDINGS=()

# Counters for non-JSON mode
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

# Finding functions
add_finding() {
    local severity="$1"
    local category="$2"
    local message="$3"
    local details="${4:-}"

    # Track counts regardless of output mode
    case "$severity" in
        "CRITICAL") CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        "WARNING")  WARNING_COUNT=$((WARNING_COUNT + 1)) ;;
        "INFO")     INFO_COUNT=$((INFO_COUNT + 1)) ;;
    esac

    if [ "$JSON_OUTPUT" = true ]; then
        FINDINGS+=("{\"severity\":\"$severity\",\"category\":\"$category\",\"message\":\"$message\",\"details\":\"$details\"}")
    else
        case "$severity" in
            "CRITICAL") echo -e "$CRITICAL $message" ;;
            "WARNING")  echo -e "$WARNING $message" ;;
            "INFO")     echo -e "$INFO $message" ;;
        esac
        if [ -n "$details" ]; then
            echo "   Details: $details"
        fi
    fi
}

# Get hostname from metadata
HOSTNAME=$(jq -r '.hostname // "unknown"' "$EXTRACT_DIR/metadata.json" 2>/dev/null || echo "unknown")

if [ "$JSON_OUTPUT" != true ]; then
    echo "========================================"
    echo "FORENSIC ARTIFACT ANALYSIS"
    echo "========================================"
    echo "Host: $HOSTNAME"
    echo "Tarball: $TARBALL"
    echo "Time: $(date)"
    echo "========================================"
    echo ""
fi

# ==============================================================================
# CRITICAL CHECKS
# ==============================================================================

# Check ld.so.preload (rootkit indicator)
if [ -f "$EXTRACT_DIR/persistence/ld.so.preload" ]; then
    content=$(cat "$EXTRACT_DIR/persistence/ld.so.preload" | grep -v "^#" | grep -v "^$" | head -1)
    if [ -n "$content" ] && [ "$content" != "File does not exist (normal)" ]; then
        add_finding "CRITICAL" "rootkit" "ld.so.preload contains entries - possible rootkit" "$content"
    fi
fi

# Check for UID 0 users other than root
# Exclude legitimate RHEL system accounts with UID 0
LEGIT_UID0="root|sync|shutdown|halt|operator"
if [ -f "$EXTRACT_DIR/users/passwd" ]; then
    # UID is the 3rd field (index 2), check for UID exactly 0
    uid0_users=$(awk -F: '$3 == 0 {print $1}' "$EXTRACT_DIR/users/passwd" | grep -vE "^($LEGIT_UID0)$")
    if [ -n "$uid0_users" ]; then
        for user in $uid0_users; do
            add_finding "CRITICAL" "privilege" "User '$user' has UID 0 (root equivalent)" "Check /etc/passwd for unauthorized root accounts"
        done
    fi
fi

# Check for users with no password (empty second field in shadow)
if [ -f "$EXTRACT_DIR/users/shadow" ]; then
    nopass_users=$(awk -F: '$2 == "" {print $1}' "$EXTRACT_DIR/users/shadow")
    if [ -n "$nopass_users" ]; then
        for user in $nopass_users; do
            add_finding "CRITICAL" "auth" "User '$user' has no password set" "Immediate password reset required"
        done
    fi
fi

# ==============================================================================
# WARNING CHECKS
# ==============================================================================

# Check for suspicious cron jobs
if [ -f "$EXTRACT_DIR/persistence/cron/user_crontabs.txt" ]; then
    # curl | bash patterns
    if grep -qE "curl.*\|.*sh|wget.*\|.*sh" "$EXTRACT_DIR/persistence/cron/user_crontabs.txt"; then
        match=$(grep -oE "curl.*\|.*sh|wget.*\|.*sh" "$EXTRACT_DIR/persistence/cron/user_crontabs.txt" | head -1)
        add_finding "WARNING" "persistence" "Suspicious cron job found: curl/wget piped to shell" "$match"
    fi
fi

# Check cron.d directory
if [ -d "$EXTRACT_DIR/persistence/cron/cron.d" ]; then
    for cronfile in "$EXTRACT_DIR/persistence/cron/cron.d"/*; do
        if [ -f "$cronfile" ]; then
            if grep -qE "curl.*\|.*sh|wget.*\|.*sh|nc |ncat|/dev/tcp" "$cronfile" 2>/dev/null; then
                add_finding "WARNING" "persistence" "Suspicious cron.d file: $(basename $cronfile)" "Contains shell download/execution patterns"
            fi
        fi
    done
fi

# Check for unauthorized SSH keys
if [ -f "$EXTRACT_DIR/users/ssh_keys/authorized_keys_all.txt" ]; then
    # Check for common malicious key comments
    if grep -qiE "attacker|evil|backdoor|hacker|pwned" "$EXTRACT_DIR/users/ssh_keys/authorized_keys_all.txt"; then
        add_finding "WARNING" "auth" "Suspicious SSH authorized_key found" "Check for unauthorized SSH keys"
    fi

    # Count total keys
    key_count=$(grep -c "^ssh-" "$EXTRACT_DIR/users/ssh_keys/authorized_keys_all.txt" 2>/dev/null || echo 0)
    if [ "$key_count" -gt 5 ]; then
        add_finding "INFO" "auth" "Multiple SSH keys found ($key_count total)" "Review authorized_keys for legitimacy"
    fi
fi

# Check for users with suspicious home directories
# Can't check if directory exists (analyzing offline), but can check for suspicious patterns
if [ -f "$EXTRACT_DIR/users/passwd" ]; then
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ]; then
            # Flag users with clearly suspicious home directories
            if echo "$homedir" | grep -qE "^/(nonexistent|dev/null|bin/false|tmp|var/tmp|dev/shm)"; then
                add_finding "WARNING" "user" "User '$username' (UID $uid) has suspicious home directory" "$homedir"
            fi
        fi
    done < "$EXTRACT_DIR/users/passwd"
fi

# Check for suspicious systemd services
if [ -d "$EXTRACT_DIR/persistence/systemd/custom_services" ]; then
    for svc in "$EXTRACT_DIR/persistence/systemd/custom_services"/*.service; do
        if [ -f "$svc" ]; then
            svc_name=$(basename "$svc")
            # Check for suspicious patterns in service
            if grep -qiE "curl|wget|nc |ncat|reverse|shell|backdoor|evil|hack" "$svc" 2>/dev/null; then
                add_finding "WARNING" "persistence" "Suspicious systemd service: $svc_name" "Contains suspicious commands"
            fi
            # Check for services running bash loops
            if grep -qE "while.*true.*do.*sleep" "$svc" 2>/dev/null; then
                add_finding "WARNING" "persistence" "Service '$svc_name' runs infinite loop" "Possible beacon or backdoor"
            fi
        fi
    done
fi

# Check for suspicious network listeners
if [ -f "$EXTRACT_DIR/network/ss_tulpan.txt" ]; then
    # Common backdoor ports
    for port in 4444 4445 4446 5555 6666 1337 31337; do
        if grep -qE ":$port\s" "$EXTRACT_DIR/network/ss_tulpan.txt"; then
            add_finding "WARNING" "network" "Suspicious listener on port $port" "Common backdoor/reverse shell port"
        fi
    done

    # Check for listeners on all interfaces
    all_listen=$(grep "0.0.0.0:\|*:" "$EXTRACT_DIR/network/ss_tulpan.txt" | grep LISTEN | wc -l)
    if [ "$all_listen" -gt 10 ]; then
        add_finding "INFO" "network" "Many services listening on all interfaces ($all_listen)" "Review for unnecessary exposure"
    fi
fi

# Check profile.d for backdoors
if [ -d "$EXTRACT_DIR/shell/profiles/profile.d" ]; then
    for profile in "$EXTRACT_DIR/shell/profiles/profile.d"/*; do
        if [ -f "$profile" ]; then
            if grep -qiE "curl|wget|nc |ncat|/dev/tcp|reverse|shell|backdoor" "$profile" 2>/dev/null; then
                add_finding "WARNING" "persistence" "Suspicious profile.d script: $(basename $profile)" "Contains shell/network commands"
            fi
        fi
    done
fi

# Check shell histories for suspicious commands
for history in "$EXTRACT_DIR/shell/histories"/*; do
    if [ -f "$history" ]; then
        # Check for common attack patterns
        if grep -qE "curl.*\|.*sh|wget.*\|.*sh|nc -e|ncat -e|/dev/tcp|reverse|base64.*-d|python.*socket|perl.*socket" "$history" 2>/dev/null; then
            user=$(basename "$history" | sed 's/_.*//')
            add_finding "WARNING" "history" "Suspicious commands in ${user}'s history" "Review shell history for attack indicators"
        fi
    fi
done

# Check for hidden files in /tmp
if [ -f "$EXTRACT_DIR/files/tmp_hidden.txt" ]; then
    hidden_count=$(wc -l < "$EXTRACT_DIR/files/tmp_hidden.txt" 2>/dev/null | tr -d ' ')
    if [ "$hidden_count" -gt 0 ] 2>/dev/null; then
        add_finding "WARNING" "files" "Hidden files found in /tmp ($hidden_count files)" "Review for malware or data exfiltration staging"
    fi
fi

# Check for world-writable system files
if [ -f "$EXTRACT_DIR/files/world_writable.txt" ]; then
    ww_count=$(wc -l < "$EXTRACT_DIR/files/world_writable.txt" 2>/dev/null | tr -d ' ')
    if [ "$ww_count" -gt 0 ] 2>/dev/null; then
        add_finding "WARNING" "files" "World-writable files in system directories ($ww_count files)" "Security misconfiguration - review permissions"
    fi
fi

# Check for SUID binaries in non-standard locations
if [ -f "$EXTRACT_DIR/files/suid_nonstandard.txt" ]; then
    suid_count=$(wc -l < "$EXTRACT_DIR/files/suid_nonstandard.txt" 2>/dev/null | tr -d ' ')
    if [ "$suid_count" -gt 0 ] 2>/dev/null; then
        add_finding "WARNING" "files" "SUID/SGID binaries in non-standard locations ($suid_count)" "Possible privilege escalation vectors"
    fi
fi

# ==============================================================================
# INFO CHECKS
# ==============================================================================

# Check loaded kernel modules
if [ -f "$EXTRACT_DIR/system/lsmod.txt" ]; then
    # Known suspicious module names
    if grep -qiE "hide|rootkit|stealth|backdoor" "$EXTRACT_DIR/system/lsmod.txt"; then
        add_finding "INFO" "kernel" "Potentially suspicious kernel modules loaded" "Review lsmod output"
    fi
fi

# Check for recently modified system files
if [ -f "$EXTRACT_DIR/files/recently_modified_system.txt" ]; then
    recent_count=$(wc -l < "$EXTRACT_DIR/files/recently_modified_system.txt" 2>/dev/null | tr -d ' ')
    if [ "$recent_count" -gt 10 ] 2>/dev/null; then
        add_finding "INFO" "files" "Recently modified files in system dirs ($recent_count)" "Review for unauthorized changes"
    fi
fi

# Check /dev/shm
if [ -f "$EXTRACT_DIR/files/dev_shm.txt" ]; then
    shm_files=$(grep -v "^total" "$EXTRACT_DIR/files/dev_shm.txt" | grep -v "^$" | wc -l)
    if [ "$shm_files" -gt 2 ]; then
        add_finding "INFO" "files" "Files present in /dev/shm ($shm_files)" "In-memory storage sometimes used by malware"
    fi
fi

# ==============================================================================
# OUTPUT
# ==============================================================================

if [ "$JSON_OUTPUT" = true ]; then
    # Output JSON
    echo "{"
    echo "  \"hostname\": \"$HOSTNAME\","
    echo "  \"analysis_time\": \"$(date -Iseconds)\","
    echo "  \"tarball\": \"$TARBALL\","
    echo "  \"findings\": ["
    first=true
    for finding in "${FINDINGS[@]:-}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        echo -n "    $finding"
    done
    echo ""
    echo "  ]"
    echo "}"
else
    echo ""
    echo "========================================"
    echo "ANALYSIS COMPLETE"
    echo "========================================"

    echo -e "Critical: ${RED}$CRITICAL_COUNT${NC}"
    echo -e "Warnings: ${YELLOW}$WARNING_COUNT${NC}"
    echo -e "Info:     ${CYAN}$INFO_COUNT${NC}"
    echo ""

    if [ $CRITICAL_COUNT -gt 0 ]; then
        echo -e "${RED}IMMEDIATE ACTION REQUIRED - Critical findings detected!${NC}"
        exit 2
    elif [ $WARNING_COUNT -gt 0 ]; then
        echo -e "${YELLOW}Review recommended - Warnings detected${NC}"
        exit 1
    else
        echo -e "${GREEN}No major issues detected${NC}"
        exit 0
    fi
fi
