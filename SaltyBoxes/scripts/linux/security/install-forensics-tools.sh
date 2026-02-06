#!/usr/bin/env bash
set -euo pipefail
# ==============================================================================
# Script Name: install-forensics-tools.sh
# Description: Installs forensic and security analysis tools for incident
#              response. Includes scanners, analysis tools, external utilities
#              (Volatility3, AVML, UAC), and YARA community rules.
#
# Author: Samuel Brucker 2025-2026
# Version: 1.0
#
# Supported Systems:
#   - Ubuntu/Debian (apt)
#   - Fedora/RHEL/Oracle/Rocky/Alma (dnf/yum)
#   - Arch (pacman)
#   - Alpine (apk)
#
# Usage:
#   sudo ./install-forensics-tools.sh
#
# Output Markers:
#   [RESULT] INSTALLED: toolname  - Tool was freshly installed
#   [RESULT] PRESENT: toolname    - Tool already present
#   [RESULT] FAILED: toolname     - Tool installation failed
#
# ==============================================================================

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors (disabled when not a TTY)
if [[ -t 1 ]]; then
    BLUE='\033[0;34m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    BLUE='' GREEN='' YELLOW='' RED='' NC=''
fi

log()     { echo -e "${GREEN}[INFO]${NC} ${1:-}"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} ${1:-}"; }
err()     { echo -e "${RED}[ERROR]${NC} ${1:-}"; }
section() { echo -e "\n${BLUE}========== ${1:-} ==========${NC}"; }

command_exists() { command -v "$1" > /dev/null 2>&1; }

FAIL_COUNT=0
INSTALL_COUNT=0
PRESENT_COUNT=0

# Detect distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
else
    DISTRO_ID="unknown"
fi

# Determine package manager
if command_exists apt-get; then
    PKG="apt"
elif command_exists dnf; then
    PKG="dnf"
elif command_exists yum; then
    PKG="yum"
elif command_exists pacman; then
    PKG="pacman"
elif command_exists apk; then
    PKG="apk"
else
    echo "Error: No supported package manager found."
    exit 1
fi

# Helper: install packages by distro (logs stderr, tracks failures)
install_pkgs() {
    local rc=0
    case "$PKG" in
        apt)    apt-get install -y "$@" 2>&1 || rc=$? ;;
        dnf)    dnf install -y "$@" 2>&1 || rc=$? ;;
        yum)    yum install -y "$@" 2>&1 || rc=$? ;;
        pacman) pacman -S --noconfirm "$@" 2>&1 || rc=$? ;;
        apk)    apk add "$@" 2>&1 || rc=$? ;;
    esac
    if [[ $rc -ne 0 ]]; then
        warn "Package install returned exit code $rc for: $*"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

# Helper: check if tool was installed (for result tracking)
check_tool() {
    local tool="$1"
    local cmd="${2:-$tool}"
    if command_exists "$cmd"; then
        return 0
    fi
    return 1
}

# =========================================================================
# 1. FORENSIC SCANNERS
# =========================================================================
section "FORENSIC SCANNERS"
log "Installing rootkit detectors, antivirus, and integrity checkers..."

export DEBIAN_FRONTEND=noninteractive

if [[ "$PKG" == "apt" ]]; then
    apt-get update -y 2>&1 | tail -5
    install_pkgs rkhunter chkrootkit clamav clamav-daemon \
        aide yara unhide debsums
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs epel-release 2>/dev/null || true
    # Install individually to handle missing packages
    for pkg in rkhunter chkrootkit clamav clamd clamav-update aide yara unhide; do
        install_pkgs "$pkg" 2>/dev/null || warn "$pkg not available in repos"
    done
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs rkhunter clamav aide yara unhide
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs rkhunter clamav yara
fi

log "Forensic scanners installation complete."

# =========================================================================
# 2. ANALYSIS TOOLS
# =========================================================================
section "ANALYSIS TOOLS"
log "Installing binary analysis, syscall tracing, and forensic tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs strace ltrace xxd sleuthkit binutils
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    # xxd is part of vim-common on RHEL
    install_pkgs strace ltrace vim-common sleuthkit binutils
elif [[ "$PKG" == "pacman" ]]; then
    # xxd is part of vim on Arch
    install_pkgs strace ltrace vim sleuthkit binutils
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs strace ltrace xxd sleuthkit binutils
fi

log "Analysis tools installation complete."

# =========================================================================
# 3. NETWORK TOOLS
# =========================================================================
section "NETWORK TOOLS"
log "Installing network forensics tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs tcpdump lsof net-tools
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs tcpdump lsof net-tools
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs tcpdump lsof net-tools
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs tcpdump lsof net-tools
fi

log "Network tools installation complete."

# =========================================================================
# 4. AUDIT TOOLS
# =========================================================================
section "AUDIT TOOLS"
log "Installing system auditing tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs auditd
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs audit
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs audit
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs audit
fi

# Enable and configure auditd
if command_exists auditctl; then
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    # Add minimal forensic-relevant watches as fallback
    auditctl -w /etc/passwd -p wa -k user_changes 2>/dev/null || true
    auditctl -w /etc/shadow -p wa -k shadow_changes 2>/dev/null || true
    auditctl -w /etc/sudoers -p wa -k sudoers_changes 2>/dev/null || true
    auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config 2>/dev/null || true
    auditctl -w /etc/crontab -p wa -k crontab_changes 2>/dev/null || true
    auditctl -w /etc/cron.d/ -p wa -k cron_d_changes 2>/dev/null || true
    auditctl -w /etc/ld.so.preload -p wa -k ld_preload 2>/dev/null || true
    auditctl -w /tmp -p x -k tmp_exec 2>/dev/null || true
    auditctl -w /dev/shm -p x -k shm_exec 2>/dev/null || true
    log "auditd enabled with forensic watches"
fi

log "Audit tools installation complete."

# =========================================================================
# 5. BUILD DEPENDENCIES
# =========================================================================
section "BUILD DEPENDENCIES"
log "Installing build dependencies for external tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs git python3 python3-pip python3-venv wget curl
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs git python3 python3-pip wget curl
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs git python python-pip wget curl
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs git python3 py3-pip wget curl
fi

log "Build dependencies installation complete."

# =========================================================================
# 6. VOLATILITY3 (in venv)
# =========================================================================
section "VOLATILITY3"
log "Installing Volatility3 into /opt/volatility3-venv..."

VENV_DIR="/opt/volatility3-venv"
if command_exists python3; then
    if [[ ! -f "$VENV_DIR/bin/vol" ]]; then
        python3 -m venv "$VENV_DIR" 2>/dev/null || warn "Failed to create venv at $VENV_DIR"
        if [[ -f "$VENV_DIR/bin/pip" ]]; then
            "$VENV_DIR/bin/pip" install --upgrade pip 2>&1 | tail -3 || true
            "$VENV_DIR/bin/pip" install volatility3 2>&1 | tail -5 || warn "Volatility3 pip install failed (non-fatal)"
            if [[ -f "$VENV_DIR/bin/vol" ]]; then
                ln -sf "$VENV_DIR/bin/vol" /usr/local/bin/vol
                log "Volatility3 installed; 'vol' linked to /usr/local/bin/vol"
            fi
        fi
    else
        log "Volatility3 already installed."
    fi
else
    warn "python3 not available, skipping Volatility3"
fi

# =========================================================================
# 6b. VOLATILITY3 SYMBOL TABLES (for Linux memory analysis)
# =========================================================================
section "VOLATILITY3 SYMBOLS"
log "Setting up Volatility3 symbol tables for Linux memory analysis..."

VOL_SYMBOLS_DIR="/opt/volatility3-venv/lib/python3*/site-packages/volatility3/symbols"
# Find actual symbols dir
VOL_SYMBOLS_DIR=$(find /opt/volatility3-venv -type d -name "symbols" 2>/dev/null | grep volatility3 | head -1)

if [[ -z "$VOL_SYMBOLS_DIR" ]]; then
    VOL_SYMBOLS_DIR="/opt/volatility3-venv/symbols"
    mkdir -p "$VOL_SYMBOLS_DIR"
fi

# Install dwarf2json if not present
DWARF2JSON="/usr/local/bin/dwarf2json"
if [[ ! -f "$DWARF2JSON" ]]; then
    log "Installing dwarf2json for symbol generation..."
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        DWARF2JSON_URL="https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-amd64"
    elif [[ "$ARCH" == "aarch64" ]]; then
        DWARF2JSON_URL="https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-arm64"
    else
        warn "dwarf2json not available for architecture: $ARCH"
        DWARF2JSON_URL=""
    fi

    if [[ -n "$DWARF2JSON_URL" ]]; then
        if wget -q -O "$DWARF2JSON" "$DWARF2JSON_URL" 2>/dev/null; then
            chmod +x "$DWARF2JSON"
            log "dwarf2json installed to $DWARF2JSON"
        else
            local dwarf_vendor="$SCRIPT_DIR/../../../../vendor/dwarf2json/dwarf2json-linux-amd64"
            if [[ -f "$dwarf_vendor" ]]; then
                cp "$dwarf_vendor" "$DWARF2JSON"
                chmod +x "$DWARF2JSON"
                log "dwarf2json installed from vendored local copy"
            else
                warn "dwarf2json download failed and no vendor copy found"
            fi
        fi
    fi
else
    log "dwarf2json already installed"
fi

# Install kernel debug symbols (needed for ISF generation)
KERNEL_VERSION=$(uname -r)
VMLINUX=""

# Find vmlinux with debug symbols
for path in \
    "/usr/lib/debug/boot/vmlinux-$KERNEL_VERSION" \
    "/usr/lib/debug/lib/modules/$KERNEL_VERSION/vmlinux" \
    "/boot/vmlinux-$KERNEL_VERSION" \
    "/lib/modules/$KERNEL_VERSION/build/vmlinux"; do
    if [[ -f "$path" ]]; then
        VMLINUX="$path"
        break
    fi
done

# Try to install debug symbols if not found
if [[ -z "$VMLINUX" ]]; then
    log "Installing kernel debug symbols for $KERNEL_VERSION..."
    case "$PKG" in
        apt)
            # Enable debug symbol repository if needed
            if ! grep -q "ddebs.ubuntu.com" /etc/apt/sources.list.d/*.list 2>/dev/null; then
                echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" > /etc/apt/sources.list.d/ddebs.list 2>/dev/null || true
                echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/ddebs.list 2>/dev/null || true
                apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 2>/dev/null || true
                apt-get update -qq 2>/dev/null || true
            fi
            apt-get install -y "linux-image-$KERNEL_VERSION-dbgsym" 2>/dev/null || \
            apt-get install -y "linux-image-$(uname -r | sed 's/-generic//')-dbgsym" 2>/dev/null || \
            warn "Kernel debug symbols not available in repos"
            ;;
        dnf|yum)
            debuginfo-install -y "kernel-$KERNEL_VERSION" 2>/dev/null || \
            $PKG install -y "kernel-debuginfo-$KERNEL_VERSION" 2>/dev/null || \
            warn "Kernel debuginfo not available"
            ;;
    esac

    # Re-check for vmlinux
    for path in \
        "/usr/lib/debug/boot/vmlinux-$KERNEL_VERSION" \
        "/usr/lib/debug/lib/modules/$KERNEL_VERSION/vmlinux"; do
        if [[ -f "$path" ]]; then
            VMLINUX="$path"
            break
        fi
    done
fi

# Generate ISF symbol file
ISF_FILE="$VOL_SYMBOLS_DIR/linux/linux-$KERNEL_VERSION.json"
if [[ -f "$DWARF2JSON" ]] && [[ -n "$VMLINUX" ]]; then
    if [[ ! -f "$ISF_FILE" ]] && [[ ! -f "$ISF_FILE.xz" ]]; then
        # dwarf2json needs ~7-8x vmlinux size in memory (720MB vmlinux = ~5.5GB total)
        # Plus ~500MB system overhead during processing
        AVAIL_MEM_MB=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
        TOTAL_SWAP_MB=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
        VMLINUX_SIZE_MB=$(stat -c%s "$VMLINUX" 2>/dev/null | awk '{print int($1/1024/1024)}' || echo 0)
        NEEDED_MEM_MB=$((VMLINUX_SIZE_MB * 8 + 512))  # 8x vmlinux + 512MB overhead

        log "Generating Volatility3 symbols for kernel $KERNEL_VERSION..."
        log "  vmlinux: $VMLINUX (${VMLINUX_SIZE_MB}MB)"
        log "  Available RAM: ${AVAIL_MEM_MB}MB, Swap: ${TOTAL_SWAP_MB}MB, estimated need: ${NEEDED_MEM_MB}MB"

        mkdir -p "$VOL_SYMBOLS_DIR/linux"

        # Check if we have enough RAM+swap, create swap if needed
        TOTAL_AVAIL_MB=$((AVAIL_MEM_MB + TOTAL_SWAP_MB))
        SWAPFILE="/swapfile_dwarf"
        CREATED_SWAP=0

        if [[ $TOTAL_AVAIL_MB -lt $NEEDED_MEM_MB ]]; then
            # Try to create temporary swap to allow symbol generation
            # Use at least 4GB or enough to meet needs with 1GB buffer
            SWAP_NEEDED_MB=$((NEEDED_MEM_MB - TOTAL_AVAIL_MB + 1024))
            [[ $SWAP_NEEDED_MB -lt 4096 ]] && SWAP_NEEDED_MB=4096  # Minimum 4GB swap
            log "Creating temporary swap (${SWAP_NEEDED_MB}MB) for symbol generation..."

            # Check available disk space
            DISK_FREE_MB=$(df -m / | awk 'NR==2 {print $4}')
            if [[ $DISK_FREE_MB -gt $((SWAP_NEEDED_MB + 1024)) ]]; then
                if fallocate -l "${SWAP_NEEDED_MB}M" "$SWAPFILE" 2>/dev/null || \
                   dd if=/dev/zero of="$SWAPFILE" bs=1M count=$SWAP_NEEDED_MB status=none 2>/dev/null; then
                    chmod 600 "$SWAPFILE"
                    mkswap "$SWAPFILE" >/dev/null 2>&1
                    swapon "$SWAPFILE" 2>/dev/null && CREATED_SWAP=1
                    log "Temporary swap created and enabled"
                else
                    warn "Failed to create swap file"
                fi
            else
                warn "Insufficient disk space for temporary swap (have ${DISK_FREE_MB}MB, need ${SWAP_NEEDED_MB}MB)"
            fi
        fi

        # Proceed with symbol generation (with or without new swap)
        if [[ $((AVAIL_MEM_MB + TOTAL_SWAP_MB + (CREATED_SWAP * SWAP_NEEDED_MB))) -ge $((NEEDED_MEM_MB / 2)) ]]; then
            if timeout 900 "$DWARF2JSON" linux --elf "$VMLINUX" > "$VOL_SYMBOLS_DIR/linux/linux-$KERNEL_VERSION.json" 2>/dev/null; then
                # Verify file is not empty
                if [[ -s "$VOL_SYMBOLS_DIR/linux/linux-$KERNEL_VERSION.json" ]]; then
                    # Compress to save space (Volatility3 can read .xz files)
                    if command_exists xz; then
                        xz -9 "$VOL_SYMBOLS_DIR/linux/linux-$KERNEL_VERSION.json" 2>/dev/null || true
                        log "Volatility3 symbols generated and compressed"
                    else
                        log "Volatility3 symbols generated (uncompressed)"
                    fi
                    echo "[RESULT] INSTALLED: volatility3-symbols"
                else
                    warn "Symbol generation produced empty file"
                    rm -f "$VOL_SYMBOLS_DIR/linux/linux-$KERNEL_VERSION.json"
                    echo "[RESULT] FAILED: volatility3-symbols"
                fi
            else
                warn "Symbol generation failed or timed out (may need more RAM/time)"
                rm -f "$VOL_SYMBOLS_DIR/linux/linux-$KERNEL_VERSION.json"
                echo "[RESULT] FAILED: volatility3-symbols"
            fi
        else
            warn "Insufficient memory for symbol generation"
            warn "Consider generating symbols on a machine with 8GB+ RAM:"
            warn "  dwarf2json linux --elf $VMLINUX > linux-$KERNEL_VERSION.json"
            warn "  Then copy to: $VOL_SYMBOLS_DIR/linux/"
            echo "[RESULT] SKIPPED: volatility3-symbols (insufficient RAM)"
        fi

        # Clean up temporary swap if we created it
        if [[ $CREATED_SWAP -eq 1 ]]; then
            log "Cleaning up temporary swap..."
            swapoff "$SWAPFILE" 2>/dev/null || true
            rm -f "$SWAPFILE" 2>/dev/null || true
        fi
    else
        log "Volatility3 symbols already present for kernel $KERNEL_VERSION"
        echo "[RESULT] PRESENT: volatility3-symbols"
    fi
elif [[ ! -f "$DWARF2JSON" ]]; then
    warn "dwarf2json not available - cannot generate symbols"
    echo "[RESULT] FAILED: volatility3-symbols (no dwarf2json)"
elif [[ -z "$VMLINUX" ]]; then
    warn "Kernel debug symbols not found for $KERNEL_VERSION"
    warn "  Install manually: apt install linux-image-$KERNEL_VERSION-dbgsym"
    warn "  Or for RHEL: debuginfo-install kernel-$KERNEL_VERSION"
    echo "[RESULT] FAILED: volatility3-symbols (no vmlinux)"
fi

# =========================================================================
# 7. AVML
# =========================================================================
section "AVML"
log "Installing AVML memory acquisition tool..."

if [[ ! -f /usr/local/bin/avml ]]; then
    AVML_URL="https://github.com/microsoft/avml/releases/latest/download/avml"
    AVML_VENDOR="$SCRIPT_DIR/../../../../vendor/avml/avml"
    AVML_TMP="$(mktemp /tmp/avml.XXXXXXXXXX)"

    # Check architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]]; then
        warn "AVML only supports x86_64 (current: $ARCH), skipping"
    elif wget -q -O "$AVML_TMP" "$AVML_URL" 2>/dev/null; then
        mv "$AVML_TMP" /usr/local/bin/avml
        chmod +x /usr/local/bin/avml
        log "AVML installed to /usr/local/bin/avml"
    elif [[ -f "$AVML_VENDOR" ]]; then
        rm -f "$AVML_TMP"
        cp "$AVML_VENDOR" /usr/local/bin/avml
        chmod +x /usr/local/bin/avml
        log "AVML installed from vendored local copy"
    else
        rm -f "$AVML_TMP" 2>/dev/null || true
        warn "AVML download failed and no vendor copy found (non-fatal)"
    fi
else
    log "AVML already installed."
fi

# =========================================================================
# 8. UAC (Unix-like Artifacts Collector)
# =========================================================================
section "UAC"
log "Installing UAC (Unix-like Artifacts Collector)..."

if [[ ! -d /opt/uac ]]; then
    local uac_installed=false
    if command_exists git; then
        if git clone --depth 1 https://github.com/tclahr/uac /opt/uac 2>/dev/null; then
            chmod +x /opt/uac/uac 2>/dev/null || true
            log "UAC installed to /opt/uac"
            uac_installed=true
        fi
    fi
    if [[ "$uac_installed" == "false" ]]; then
        local uac_vendor="$SCRIPT_DIR/../../../../vendor/uac/source"
        if [[ -d "$uac_vendor" ]]; then
            cp -r "$uac_vendor" /opt/uac
            chmod +x /opt/uac/uac 2>/dev/null || true
            log "UAC installed from vendored local copy"
        else
            warn "UAC clone failed and no vendor copy found"
        fi
    fi
else
    log "UAC already installed."
fi

# =========================================================================
# 9. YARA COMMUNITY RULES
# =========================================================================
section "YARA RULES"
log "Downloading YARA community rules..."

if command_exists yara; then
    YARA_DIR="/etc/yara"
    if [[ ! -f "$YARA_DIR/master_community_rules.yar" ]]; then
        CLONE_DIR="/tmp/signature-base-$$"
        mkdir -p "$YARA_DIR"
        rm -rf "$CLONE_DIR"

        local yara_vendor="$SCRIPT_DIR/../../../../vendor/yara-rules/source"
        local yara_cloned=false
        if command_exists git && git clone --depth 1 https://github.com/neo23x0/signature-base.git "$CLONE_DIR" 2>/dev/null; then
            yara_cloned=true
        elif [[ -d "$yara_vendor" ]]; then
            cp -r "$yara_vendor" "$CLONE_DIR"
            log "Using vendored YARA rules"
            yara_cloned=true
        fi
        if [[ "$yara_cloned" == "true" ]]; then
            # Remove problematic rules that break compilation
            for pattern in "*3cx*" "*screenconnect*" "*vcruntime*" "*base64_pe*" "*poisonivy*" "*Linux_Sudops*" \
                "*gen_susp_obfuscation.yar*" "*apt_barracuda_esg_unc4841_jun23.yar*" "*apt_cobaltstrike.yar*" \
                "*apt_tetris.yar*" "*configured_vulns_ext_vars.yar*" "*expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar*" \
                "*expl_cleo_dec24.yar*" "*expl_commvault_cve_2025_57791.yar*" "*expl_outlook_cve_2023_23397.yar*" \
                "*gen_fake_amsi_dll.yar*" "*gen_gcti_cobaltstrike.yar*" "*gen_susp_js_obfuscatorio.yar*" \
                "*gen_susp_xor.yar*" "*gen_webshells_ext_vars.yar*" "*gen_xor_hunting.yar*" "*general_cloaking.yar*" \
                "*generic_anomalies.yar*" "*mal_lockbit_lnx_macos_apr23.yar*" "*thor-hacktools.yar*" \
                "*thor_inverse_matches.yar*" "*vuln_paloalto_cve_2024_3400_apr24.yar*" \
                "*yara-rules_vuln_drivers_strict_renamed.yar*" "*yara_mixed_ext_vars.yar*"; do
                find "$CLONE_DIR/yara" -type f -name "$pattern" -delete 2>/dev/null || true
            done

            # Combine into master rule file
            find "$CLONE_DIR/yara" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 | \
                xargs -0 cat > "$YARA_DIR/master_community_rules.yar" 2>/dev/null
            chmod 644 "$YARA_DIR/master_community_rules.yar"
            rm -rf "$CLONE_DIR"

            if yara -C "$YARA_DIR/master_community_rules.yar" /dev/null 2>/dev/null; then
                log "YARA rules compiled successfully"
            else
                warn "YARA rules have compilation warnings (partial rules still usable)"
            fi
        else
            warn "YARA rules download failed and no vendor copy found"
        fi
    else
        log "YARA rules already present"
    fi
else
    warn "yara not installed, skipping rules download"
fi

# =========================================================================
# 10. DATABASE UPDATES
# =========================================================================
section "DATABASE UPDATES"
log "Updating scanner databases..."

# ClamAV
if command_exists freshclam; then
    if [[ ! -f /var/lib/clamav/main.cvd ]] && [[ ! -f /var/lib/clamav/main.cld ]]; then
        log "Initializing ClamAV database..."
        timeout 120 freshclam --quiet 2>/dev/null || warn "freshclam update skipped/failed"
    else
        log "ClamAV database already initialized"
    fi
fi

# rkhunter
if command_exists rkhunter; then
    rkhunter --update 2>&1 | tail -3 || warn "rkhunter --update failed (may already be current)"
    rkhunter --propupd 2>&1 | tail -3 || warn "rkhunter --propupd failed"
    log "rkhunter file properties updated."
fi

# AIDE
if command_exists aide; then
    AIDE_CONF=""
    [[ -f /etc/aide/aide.conf ]] && AIDE_CONF="--config /etc/aide/aide.conf"
    if [[ ! -f /var/lib/aide/aide.db ]] && [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        log "Initializing AIDE database..."
        aide --init $AIDE_CONF 2>/dev/null || true
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            log "AIDE database initialized"
        elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            log "AIDE database initialized"
        else
            warn "AIDE init may have failed"
        fi
    else
        log "AIDE database already present"
    fi
fi

# =========================================================================
# POST-INSTALL VERIFICATION
# =========================================================================
section "VERIFICATION"
log "Verifying tool installation..."

# List of tools to verify with their check commands
declare -A TOOLS=(
    ["rkhunter"]="rkhunter"
    ["chkrootkit"]="chkrootkit"
    ["clamscan"]="clamscan"
    ["aide"]="aide"
    ["yara"]="yara"
    ["unhide"]="unhide"
    ["strace"]="strace"
    ["ltrace"]="ltrace"
    ["xxd"]="xxd"
    ["strings"]="strings"
    ["tcpdump"]="tcpdump"
    ["lsof"]="lsof"
    ["auditctl"]="auditctl"
    ["avml"]="avml"
    ["vol"]="vol"
)

# Debian-specific
if [[ "$PKG" == "apt" ]]; then
    TOOLS["debsums"]="debsums"
fi

for tool in "${!TOOLS[@]}"; do
    cmd="${TOOLS[$tool]}"
    if command_exists "$cmd"; then
        echo "[RESULT] PRESENT: $tool"
        PRESENT_COUNT=$((PRESENT_COUNT + 1))
    else
        echo "[RESULT] FAILED: $tool"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

# Check Volatility3 symbols
VOL_SYMBOLS_CHECK=$(find /opt/volatility3-venv -name "linux-*.json*" 2>/dev/null | head -1)
if [[ -n "$VOL_SYMBOLS_CHECK" ]]; then
    echo "[RESULT] PRESENT: volatility3-symbols"
    PRESENT_COUNT=$((PRESENT_COUNT + 1))
fi

# Check YARA rules
if [[ -f /etc/yara/master_community_rules.yar ]]; then
    echo "[RESULT] PRESENT: yara-rules"
    PRESENT_COUNT=$((PRESENT_COUNT + 1))
else
    echo "[RESULT] FAILED: yara-rules"
fi

# Check UAC
if [[ -d /opt/uac ]]; then
    echo "[RESULT] PRESENT: uac"
    PRESENT_COUNT=$((PRESENT_COUNT + 1))
else
    echo "[RESULT] FAILED: uac"
fi

# Check Volatility3 via venv
if [[ -f /opt/volatility3-venv/bin/vol ]]; then
    echo "[RESULT] PRESENT: volatility3"
    PRESENT_COUNT=$((PRESENT_COUNT + 1))
else
    echo "[RESULT] FAILED: volatility3"
fi

# =========================================================================
# SUMMARY
# =========================================================================
section "INSTALLATION COMPLETE"
echo ""
echo "Installed tool categories:"
echo "  Scanners:  rkhunter, chkrootkit, clamav, aide, yara, unhide"
echo "  Analysis:  strace, ltrace, xxd, strings (binutils), sleuthkit"
echo "  Network:   tcpdump, lsof, net-tools"
echo "  Audit:     auditd with forensic watches"
echo "  External:  volatility3 (/opt/volatility3-venv), avml, uac"
echo "  Rules:     YARA signature-base (/etc/yara/master_community_rules.yar)"
if [[ "$PKG" == "apt" ]]; then
    echo "  Verify:    debsums (Debian/Ubuntu only)"
fi
echo ""
echo "Tools present: $PRESENT_COUNT"

if [[ $FAIL_COUNT -gt 0 ]]; then
    warn "$FAIL_COUNT tool(s) could not be installed (see [RESULT] FAILED entries above)."
    exit 1
else
    log "All tools installed successfully."
    exit 0
fi
