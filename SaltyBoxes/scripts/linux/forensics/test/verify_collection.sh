#!/bin/bash
# ==============================================================================
# Verify Forensic Collection - Test Script
# Checks that forensic collection captured the planted test artifacts
#
# Usage:
#   ./verify_collection.sh <tarball_path>
#   ./verify_collection.sh /tmp/forensics_*/hostname_forensics_*.tar.gz
#
# Returns:
#   0 - All artifacts captured
#   1 - Some artifacts missing
# ==============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
WARN="${YELLOW}[WARN]${NC}"

TARBALL="${1:-}"

if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
    echo "Usage: $0 <forensics_tarball.tar.gz>"
    echo ""
    echo "Example:"
    echo "  $0 /tmp/forensics_20260127_143000/minion_forensics_20260127_143000.tar.gz"
    exit 1
fi

echo "========================================"
echo "FORENSIC COLLECTION VERIFICATION"
echo "========================================"
echo "Tarball: $TARBALL"
echo "Time: $(date)"
echo "========================================"
echo ""

# Create temp directory for extraction
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Extract tarball
echo "Extracting tarball..."
tar -xzf "$TARBALL" -C "$TMPDIR"

# Find the extracted directory
EXTRACT_DIR=$(find "$TMPDIR" -maxdepth 1 -type d -name "*_forensics_*" | head -1)

if [ -z "$EXTRACT_DIR" ]; then
    echo -e "${FAIL} Failed to extract tarball or unexpected structure"
    exit 1
fi

echo "Extracted to: $EXTRACT_DIR"
echo ""

# Counters
TOTAL=0
PASSED=0
FAILED=0

# Verification function
check_artifact() {
    local description="$1"
    local file="$2"
    local pattern="$3"

    TOTAL=$((TOTAL + 1))

    if [ -f "$EXTRACT_DIR/$file" ]; then
        if grep -q "$pattern" "$EXTRACT_DIR/$file" 2>/dev/null; then
            echo -e "$PASS $description"
            PASSED=$((PASSED + 1))
            return 0
        else
            echo -e "$FAIL $description (pattern not found in $file)"
            FAILED=$((FAILED + 1))
            return 1
        fi
    else
        echo -e "$FAIL $description (file not found: $file)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_file_exists() {
    local description="$1"
    local file="$2"

    TOTAL=$((TOTAL + 1))

    if [ -f "$EXTRACT_DIR/$file" ]; then
        echo -e "$PASS $description"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "$FAIL $description (file not found: $file)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_file_not_empty() {
    local description="$1"
    local file="$2"

    TOTAL=$((TOTAL + 1))

    if [ -f "$EXTRACT_DIR/$file" ] && [ -s "$EXTRACT_DIR/$file" ]; then
        echo -e "$PASS $description"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "$FAIL $description (file missing or empty: $file)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

echo "=== PLANTED ARTIFACT VERIFICATION ==="
echo ""

# 1. Suspicious cron job (curl | bash)
check_artifact "Suspicious cron job captured" "persistence/cron/user_crontabs.txt" "evil.com/beacon"

# 2. Backdoor cron.d file
check_artifact "Backdoor cron.d file captured" "persistence/cron/cron.d/backdoor-job" "evil.com/malware"

# 3. Backdoor user in passwd
check_artifact "Backdoor user in passwd" "users/passwd" "^backdoor:"

# 4. Toor user (UID 0) in passwd
check_artifact "Toor user (UID 0) in passwd" "users/passwd" "^toor:.*:0:0:"

# 5. SSH authorized_keys backdoor
check_artifact "SSH backdoor key captured" "users/ssh_keys/authorized_keys_all.txt" "attacker@evil"

# 6. evil.service in systemd
if check_file_exists "evil.service file captured" "persistence/systemd/custom_services/evil.service"; then
    check_artifact "evil.service content correct" "persistence/systemd/custom_services/evil.service" "Totally Legitimate Service"
fi

# 7. evil.service in enabled list
check_artifact "evil.service in enabled services" "persistence/systemd/services_enabled.txt" "evil.service"

# 8. ld.so.preload entry
check_artifact "ld.so.preload rootkit indicator" "persistence/ld.so.preload" "libevil.so"

# 9. Shell profile backdoor
check_artifact "Profile.d backdoor captured" "shell/profiles/profile.d/backdoor.sh" "backdoor"

# 10. NC listener on port 4444
check_artifact "NC listener on port 4444" "network/ss_tulpan.txt" ":4444"

# 11. Hidden files in /tmp
check_artifact "Hidden files in /tmp captured" "files/tmp_hidden.txt" ".hidden_exfil"

# 12. Suspicious history entries
check_artifact "Suspicious history captured" "shell/histories/root_.bash_history" "evil.com/rootkit"

echo ""
echo "=== STANDARD COLLECTION VERIFICATION ==="
echo ""

# Verify standard collection files exist
check_file_not_empty "System hostname" "system/hostname"
check_file_not_empty "System uname" "system/uname.txt"
check_file_not_empty "OS release info" "system/os-release"
check_file_not_empty "Process list (ps aux)" "processes/ps_aux.txt"
check_file_not_empty "Network sockets (ss)" "network/ss_tulpan.txt"
check_file_not_empty "IP addresses" "network/ip_addr.txt"
check_file_not_empty "Routing table" "network/ip_route.txt"
check_file_not_empty "/etc/passwd copy" "users/passwd"
check_file_not_empty "Installed packages" "packages/installed_packages.txt"
check_file_exists "Metadata file" "metadata.json"

echo ""
echo "========================================"
echo "VERIFICATION SUMMARY"
echo "========================================"
echo "Total checks:  $TOTAL"
echo -e "Passed:        ${GREEN}$PASSED${NC}"
echo -e "Failed:        ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All artifacts captured successfully!${NC}"
    exit 0
else
    echo -e "${RED}Some artifacts were not captured.${NC}"
    echo "Check the collector script for issues."
    exit 1
fi
