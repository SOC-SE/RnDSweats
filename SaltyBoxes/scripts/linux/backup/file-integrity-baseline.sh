#!/bin/bash
# ==============================================================================
# File Integrity Baseline - Linux
# Create SHA256 hashes of critical system files for later comparison
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

set -euo pipefail

BASELINE_DIR="${1:-/root/baselines}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASELINE_FILE="$BASELINE_DIR/baseline_$(hostname)_$TIMESTAMP.txt"
SUMMARY_FILE="$BASELINE_DIR/baseline_$(hostname)_$TIMESTAMP.summary"

echo "========================================"
echo "FILE INTEGRITY BASELINE - $(hostname)"
echo "Time: $(date)"
echo "Output: $BASELINE_FILE"
echo "========================================"

mkdir -p "$BASELINE_DIR"

# Initialize files
echo "# File Integrity Baseline - $(hostname) - $(date)" > "$BASELINE_FILE"
echo "# Format: SHA256  FILEPATH" >> "$BASELINE_FILE"
echo "" >> "$BASELINE_FILE"

total_files=0
failed_files=0

hash_file() {
    local file="$1"
    local category="$2"

    if [ -f "$file" ] && [ -r "$file" ]; then
        hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        if [ -n "$hash" ]; then
            echo "$hash  $file" >> "$BASELINE_FILE"
            ((total_files++))
            return 0
        fi
    fi
    ((failed_files++))
    return 1
}

hash_directory() {
    local dir="$1"
    local category="$2"
    local pattern="${3:-*}"

    if [ -d "$dir" ]; then
        find "$dir" -type f -name "$pattern" 2>/dev/null | while read -r file; do
            hash_file "$file" "$category"
        done
    fi
}

echo -e "\n[1/8] CRITICAL SYSTEM BINARIES"
echo "----------------------------------------"
echo "# === CRITICAL SYSTEM BINARIES ===" >> "$BASELINE_FILE"
critical_bins=(
    /bin/bash /bin/sh /bin/login /bin/su /bin/sudo
    /usr/bin/passwd /usr/bin/ssh /usr/bin/sshd
    /usr/bin/wget /usr/bin/curl /usr/bin/nc
    /usr/sbin/useradd /usr/sbin/userdel /usr/sbin/usermod
    /usr/sbin/iptables /usr/sbin/nft
    /sbin/init /usr/lib/systemd/systemd
)
for bin in "${critical_bins[@]}"; do
    hash_file "$bin" "binary" && echo "  Hashed: $bin"
done

echo -e "\n[2/8] SUID/SGID BINARIES"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === SUID/SGID BINARIES ===" >> "$BASELINE_FILE"
find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -100 | while read -r file; do
    hash_file "$file" "suid"
done
echo "  Hashed SUID/SGID binaries"

echo -e "\n[3/8] AUTHENTICATION FILES"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === AUTHENTICATION FILES ===" >> "$BASELINE_FILE"
auth_files=(
    /etc/passwd /etc/shadow /etc/group /etc/gshadow
    /etc/sudoers /etc/login.defs
    /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/sudo
    /etc/pam.d/system-auth /etc/pam.d/password-auth
)
for f in "${auth_files[@]}"; do
    hash_file "$f" "auth" && echo "  Hashed: $f"
done
hash_directory "/etc/sudoers.d" "auth"

echo -e "\n[4/8] SSH CONFIGURATION"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === SSH CONFIGURATION ===" >> "$BASELINE_FILE"
hash_directory "/etc/ssh" "ssh" "*.conf"
hash_directory "/etc/ssh" "ssh" "*_config"
# SSH host keys
for key in /etc/ssh/ssh_host_*; do
    hash_file "$key" "ssh" && echo "  Hashed: $key"
done

echo -e "\n[5/8] SYSTEM CONFIGURATION"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === SYSTEM CONFIGURATION ===" >> "$BASELINE_FILE"
sys_configs=(
    /etc/fstab /etc/hosts /etc/hostname /etc/resolv.conf
    /etc/nsswitch.conf /etc/ld.so.conf /etc/ld.so.preload
    /etc/environment /etc/profile /etc/bashrc /etc/bash.bashrc
    /etc/sysctl.conf /etc/security/limits.conf
)
for f in "${sys_configs[@]}"; do
    hash_file "$f" "sysconfig" && echo "  Hashed: $f"
done

echo -e "\n[6/8] CRON FILES"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === CRON FILES ===" >> "$BASELINE_FILE"
hash_file "/etc/crontab" "cron"
hash_directory "/etc/cron.d" "cron"
hash_directory "/etc/cron.daily" "cron"
hash_directory "/etc/cron.hourly" "cron"
echo "  Hashed cron files"

echo -e "\n[7/8] STARTUP SCRIPTS"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === STARTUP SCRIPTS ===" >> "$BASELINE_FILE"
hash_file "/etc/rc.local" "startup"
hash_directory "/etc/init.d" "startup"
# Custom systemd units
find /etc/systemd/system -maxdepth 1 -type f -name "*.service" 2>/dev/null | while read -r file; do
    hash_file "$file" "startup"
done
echo "  Hashed startup scripts"

echo -e "\n[8/8] KERNEL MODULES"
echo "----------------------------------------"
echo "" >> "$BASELINE_FILE"
echo "# === LOADED KERNEL MODULES ===" >> "$BASELINE_FILE"
lsmod | awk 'NR>1 {print $1}' | sort > "$BASELINE_DIR/modules_$(hostname)_$TIMESTAMP.txt"
echo "  Saved loaded kernel modules list"

# Create summary
echo "========================================"
echo "BASELINE SUMMARY"
echo "========================================"
echo "Baseline created: $(date)" > "$SUMMARY_FILE"
echo "Hostname: $(hostname)" >> "$SUMMARY_FILE"
echo "Total files hashed: $total_files" >> "$SUMMARY_FILE"
echo "Files that couldn't be hashed: $failed_files" >> "$SUMMARY_FILE"
echo "Baseline file: $BASELINE_FILE" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "To verify later, run:" >> "$SUMMARY_FILE"
echo "  sha256sum -c $BASELINE_FILE 2>/dev/null | grep -v ': OK$'" >> "$SUMMARY_FILE"

cat "$SUMMARY_FILE"

echo -e "\n========================================"
echo "FILE INTEGRITY BASELINE COMPLETE"
echo "Baseline: $BASELINE_FILE"
echo "To check for changes later:"
echo "  sha256sum -c $BASELINE_FILE 2>/dev/null | grep FAILED"
echo "========================================"
