#!/bin/bash
# =============================================================================
# Full Package Update - All Linux Distributions
# =============================================================================
# Updates all installed packages to latest versions across:
#   Debian/Ubuntu (apt), RHEL/Rocky/Alma/Oracle/CentOS (dnf/yum),
#   Fedora (dnf), Alpine (apk), Devuan (apt), SUSE (zypper), Arch (pacman)
#
# Usage: ./full-package-update.sh [OPTIONS]
#   --security-only    Only apply security updates (Debian/RHEL families)
#   --dry-run          Show what would be updated without applying
#   --reboot           Reboot after update if kernel was updated
#   --clean            Clean package cache after update
#   --log              Log output to /var/log/salt-gui-update.log
# =============================================================================

set -euo pipefail

# --- Configuration ---
SECURITY_ONLY=false
DRY_RUN=false
REBOOT_IF_NEEDED=false
CLEAN_CACHE=false
LOG_FILE=""
SCRIPT_START=$(date +%s)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[UPDATE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

# --- Parse Arguments ---
for arg in "$@"; do
    case "$arg" in
        --security-only) SECURITY_ONLY=true ;;
        --dry-run)       DRY_RUN=true ;;
        --reboot)        REBOOT_IF_NEEDED=true ;;
        --clean)         CLEAN_CACHE=true ;;
        --log)           LOG_FILE="/var/log/salt-gui-update.log" ;;
        *)               warn "Unknown option: $arg" ;;
    esac
done

# Redirect to log if requested
if [[ -n "$LOG_FILE" ]]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "=== Update started: $(date -Iseconds) ===" >> "$LOG_FILE"
fi

# --- Pre-flight ---
if [[ $EUID -ne 0 ]]; then
    err "Must run as root"
    exit 1
fi

# Record kernel version before update
KERNEL_BEFORE=$(uname -r)

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v apk &>/dev/null; then
        echo "apk"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        err "No supported package manager found"
        exit 1
    fi
}

PKG_MGR=$(detect_pkg_manager)
info "Detected package manager: $PKG_MGR"
info "Hostname: $(hostname)"
info "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)"
info "Kernel: $KERNEL_BEFORE"
echo ""

# --- Count packages before ---
count_upgradable() {
    case "$PKG_MGR" in
        apt)
            apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || echo "0"
            ;;
        dnf|yum)
            $PKG_MGR check-update --quiet 2>/dev/null | grep -cE "^\S+\s+\S+\s+\S+" || echo "0"
            ;;
        apk)
            apk upgrade --simulate 2>/dev/null | grep -c "Upgrading" || echo "0"
            ;;
        zypper)
            zypper --non-interactive list-updates 2>/dev/null | grep -c "^v " || echo "0"
            ;;
        pacman)
            pacman -Qu 2>/dev/null | wc -l || echo "0"
            ;;
    esac
}

# --- Update Functions ---

update_apt() {
    log "Refreshing package index..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    local count
    count=$(count_upgradable)
    info "$count package(s) available for upgrade"

    if [[ "$count" == "0" ]]; then
        log "System is up to date"
        return 0
    fi

    if $DRY_RUN; then
        log "[DRY RUN] Would upgrade:"
        apt-get -s upgrade 2>/dev/null | grep "^Inst "
        return 0
    fi

    if $SECURITY_ONLY; then
        log "Applying security updates only..."
        # Use unattended-upgrades if available, otherwise filter manually
        if command -v unattended-upgrade &>/dev/null; then
            unattended-upgrade -v
        else
            apt-get upgrade -y -qq \
                -o Dir::Etc::SourceList=/etc/apt/sources.list \
                -o Dir::Etc::SourceParts="" \
                2>&1 | tail -20
            warn "unattended-upgrades not installed; applied all updates from main sources"
        fi
    else
        log "Upgrading all packages..."
        apt-get upgrade -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            2>&1 | tail -20

        log "Dist-upgrading (handling dependency changes)..."
        apt-get dist-upgrade -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            2>&1 | tail -20
    fi

    if $CLEAN_CACHE; then
        log "Cleaning package cache..."
        apt-get autoremove -y -qq
        apt-get autoclean -qq
    fi
}

update_dnf() {
    log "Refreshing package metadata..."
    $PKG_MGR makecache --quiet 2>/dev/null || true

    local count
    count=$(count_upgradable)
    info "$count package(s) available for upgrade"

    if [[ "$count" == "0" ]]; then
        log "System is up to date"
        return 0
    fi

    if $DRY_RUN; then
        log "[DRY RUN] Would upgrade:"
        $PKG_MGR check-update 2>/dev/null || true
        return 0
    fi

    if $SECURITY_ONLY; then
        log "Applying security updates only..."
        $PKG_MGR upgrade -y --security 2>&1 | tail -20
    else
        log "Upgrading all packages..."
        $PKG_MGR upgrade -y 2>&1 | tail -20
    fi

    if $CLEAN_CACHE; then
        log "Cleaning package cache..."
        $PKG_MGR autoremove -y 2>/dev/null || true
        $PKG_MGR clean all 2>/dev/null || true
    fi
}

update_apk() {
    log "Refreshing package index..."
    apk update --quiet

    local count
    count=$(count_upgradable)
    info "$count package(s) available for upgrade"

    if [[ "$count" == "0" ]]; then
        log "System is up to date"
        return 0
    fi

    if $DRY_RUN; then
        log "[DRY RUN] Would upgrade:"
        apk upgrade --simulate
        return 0
    fi

    log "Upgrading all packages..."
    apk upgrade --no-cache 2>&1 | tail -20

    if $CLEAN_CACHE; then
        log "Cleaning cache..."
        apk cache clean 2>/dev/null || true
    fi
}

update_zypper() {
    log "Refreshing repositories..."
    zypper --non-interactive refresh --quiet

    local count
    count=$(count_upgradable)
    info "$count package(s) available for upgrade"

    if [[ "$count" == "0" ]]; then
        log "System is up to date"
        return 0
    fi

    if $DRY_RUN; then
        log "[DRY RUN] Would upgrade:"
        zypper --non-interactive list-updates
        return 0
    fi

    log "Upgrading all packages..."
    zypper --non-interactive update --auto-agree-with-licenses 2>&1 | tail -20

    if $CLEAN_CACHE; then
        log "Cleaning cache..."
        zypper clean --all 2>/dev/null || true
    fi
}

update_pacman() {
    log "Upgrading all packages..."

    if $DRY_RUN; then
        log "[DRY RUN] Would upgrade:"
        pacman -Qu 2>/dev/null || echo "No updates available"
        return 0
    fi

    pacman -Syu --noconfirm 2>&1 | tail -20

    if $CLEAN_CACHE; then
        log "Cleaning cache..."
        pacman -Sc --noconfirm 2>/dev/null || true
    fi
}

# --- Execute Update ---
case "$PKG_MGR" in
    apt)    update_apt ;;
    dnf)    update_dnf ;;
    yum)    PKG_MGR=yum; update_dnf ;;  # yum uses same interface
    apk)    update_apk ;;
    zypper) update_zypper ;;
    pacman) update_pacman ;;
esac

# --- Post-update checks ---
echo ""

# Check if kernel was updated
KERNEL_AFTER=$(uname -r)
KERNEL_UPDATED=false

case "$PKG_MGR" in
    apt)
        NEWEST_KERNEL=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | sort -V | tail -1 | sed 's/linux-image-//')
        if [[ -n "$NEWEST_KERNEL" && "$NEWEST_KERNEL" != "$KERNEL_BEFORE" ]]; then
            KERNEL_UPDATED=true
        fi
        ;;
    dnf|yum)
        NEWEST_KERNEL=$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -1)
        if [[ -n "$NEWEST_KERNEL" && "$NEWEST_KERNEL" != "$KERNEL_BEFORE" ]]; then
            KERNEL_UPDATED=true
        fi
        ;;
esac

if $KERNEL_UPDATED; then
    warn "Kernel updated: $KERNEL_BEFORE -> $NEWEST_KERNEL"
    warn "Reboot required to use new kernel"
fi

# Check for services that need restart (Debian/Ubuntu)
if command -v needrestart &>/dev/null && ! $DRY_RUN; then
    info "Services needing restart:"
    needrestart -b 2>/dev/null | grep -E "NEEDRESTART-SVC" | head -10 || echo "  (none detected)"
fi

# --- Summary ---
SCRIPT_END=$(date +%s)
ELAPSED=$((SCRIPT_END - SCRIPT_START))

echo ""
echo "============================================"
log "Update complete in ${ELAPSED}s"
info "Hostname: $(hostname)"
info "Package manager: $PKG_MGR"
if $DRY_RUN; then
    info "Mode: DRY RUN (no changes applied)"
fi
if $SECURITY_ONLY; then
    info "Mode: Security updates only"
fi
if $KERNEL_UPDATED; then
    warn "REBOOT NEEDED (kernel updated)"
fi
echo "============================================"

# --- Reboot if requested and needed ---
if $REBOOT_IF_NEEDED && $KERNEL_UPDATED && ! $DRY_RUN; then
    warn "Rebooting in 10 seconds (--reboot flag set)..."
    sleep 10
    reboot
fi
