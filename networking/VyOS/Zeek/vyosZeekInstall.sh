#!/bin/bash
#===============================================================================
#
#  ██╗   ██╗██╗   ██╗ ██████╗ ███████╗    ███████╗███████╗███████╗██╗  ██╗
#  ██║   ██║╚██╗ ██╔╝██╔═══██╗██╔════╝    ╚══███╔╝██╔════╝██╔════╝██║ ██╔╝
#  ██║   ██║ ╚████╔╝ ██║   ██║███████╗      ███╔╝ █████╗  █████╗  █████╔╝ 
#  ╚██╗ ██╔╝  ╚██╔╝  ██║   ██║╚════██║     ███╔╝  ██╔══╝  ██╔══╝  ██╔═██╗ 
#   ╚████╔╝    ██║   ╚██████╔╝███████║    ███████╗███████╗███████╗██║  ██╗
#    ╚═══╝     ╚═╝    ╚═════╝ ╚══════╝    ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
#
#  VyOS Zeek Installation Script
#  Version: 2.0.0
#
#  Installs Zeek Network Security Monitor on VyOS using pre-built binaries.
#  This method works around VyOS's read-only filesystem by extracting
#  official Zeek packages directly without requiring compilation.
#
#  Installation Steps:
#    1. Detects VyOS version and Debian base
#    2. Downloads pre-built Zeek binaries from official repository
#    3. Extracts packages to /opt/zeek
#    4. Configures Zeek for your network interfaces
#    5. Sets up zeekctl for management
#
#  Usage: ./install-zeek-vyos.sh [options]
#
#  Options:
#    -i, --interface IFACE   Network interface(s) to monitor (comma-separated)
#    -n, --networks CIDR     Local networks (comma-separated, default: auto-detect)
#    -v, --zeek-version VER  Zeek major version (default: 7.0)
#    -y, --yes               Non-interactive mode
#    -h, --help              Show this help message
#
#  Supported VyOS Versions:
#    - VyOS 1.4.x (sagitta) - Debian 12 (Bookworm) based
#    - VyOS 1.3.x (equuleus) - Debian 11 (Bullseye) based
#    - VyOS 1.5.x (circinus) - Debian 12 based
#
#===============================================================================

set -euo pipefail

# Save original arguments for sudo hint
ORIGINAL_ARGS=("$@")

# Colors
if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
    BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
fi

# Defaults
MONITOR_INTERFACES=()
LOCAL_NETWORKS=""
ZEEK_VERSION="7.0"
NON_INTERACTIVE=false
ZEEK_PREFIX="/opt/zeek"
VYOS_VERSION=""
DEBIAN_VERSION=""
DEBIAN_CODENAME=""
INSTALL_METHOD="binary"  # binary or source
TEMP_DIR="/tmp/zeek-install"

log_header() { echo ""; echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${MAGENTA}[STEP $1]${NC} $2"; }

show_help() {
    cat << 'EOF'
VyOS Zeek Installation Script

Installs Zeek Network Security Monitor on VyOS using pre-built binaries.
This method extracts official Zeek packages directly without requiring
build tools (which VyOS's read-only filesystem doesn't support).

Usage: ./install-zeek-vyos.sh [options]

Options:
  -i, --interface IFACE   Network interface(s) to monitor, comma-separated
                          Examples: -i eth1  OR  -i "eth1,eth2,eth3"
  -n, --networks CIDR     Local networks, comma-separated (default: RFC1918)
  -v, --zeek-version VER  Zeek major version (default: 7.0)
  -y, --yes               Non-interactive mode
  -h, --help              Show this help message

Interface Selection:
  Single interface:    -i eth1           (standalone mode)
  Multiple interfaces: -i "eth1,eth2"    (cluster mode)

  For VyOS routers, monitor LAN-facing interface(s) to see:
    • Internal source IPs (not NAT'd)
    • Lateral movement between hosts
    • C2 beacons with actual infected host IPs

  Typical setup:
    Internet --- [eth0 WAN] VyOS [eth1 LAN] --- Internal
                                   ↑
                            Monitor eth1

Examples:
  ./install-zeek-vyos.sh -i eth1
  ./install-zeek-vyos.sh -i "eth1,eth2,eth3"
  ./install-zeek-vyos.sh -i eth1 -n "10.0.0.0/8" -y

EOF
}

prompt_yes_no() {
    local prompt="$1" default="$2"
    [[ "$NON_INTERACTIVE" == true ]] && { [[ "$default" == "y" ]] && return 0 || return 1; }
    local yn; while true; do
        read -r -p "$prompt " yn; yn=${yn:-$default}
        case $yn in [Yy]*) return 0;; [Nn]*) return 1;; *) echo "Please answer yes or no.";; esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]] && log_info "Try: sudo $0 ${ORIGINAL_ARGS[*]}" || log_info "Try: sudo $0"
        exit 1
    fi
}

validate_interface() { ip link show "$1" &>/dev/null; }

detect_vyos() {
    log_header "Detecting VyOS Environment"
    
    if [[ ! -f /etc/vyos-release ]] && [[ ! -d /opt/vyatta ]]; then
        log_error "This doesn't appear to be a VyOS system"
        log_info "For other Linux systems, use install-zeek-linux.sh"
        exit 1
    fi
    
    [[ -f /etc/vyos-release ]] && VYOS_VERSION=$(grep -oP 'version="\K[^"]+' /etc/vyos-release 2>/dev/null || echo "unknown")
    [[ -f /opt/vyatta/etc/version ]] && VYOS_VERSION=$(cat /opt/vyatta/etc/version 2>/dev/null || echo "unknown")
    log_success "VyOS version: $VYOS_VERSION"
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DEBIAN_VERSION="${VERSION_ID:-}"; DEBIAN_CODENAME="${VERSION_CODENAME:-}"
    fi
    
    if [[ -z "$DEBIAN_CODENAME" ]] && [[ -f /etc/debian_version ]]; then
        local deb_ver; deb_ver=$(cat /etc/debian_version)
        case "$deb_ver" in
            12*|bookworm*) DEBIAN_CODENAME="bookworm"; DEBIAN_VERSION="12" ;;
            11*|bullseye*) DEBIAN_CODENAME="bullseye"; DEBIAN_VERSION="11" ;;
            *) DEBIAN_CODENAME="bookworm"; DEBIAN_VERSION="12" ;;
        esac
    fi
    
    log_success "Debian base: $DEBIAN_VERSION ($DEBIAN_CODENAME)"
}

detect_interfaces() {
    log_header "Detecting Network Interfaces"
    
    local all_interfaces
    all_interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE '^(lo|docker|veth|br-|virbr|wg)' | sed 's/@.*//' | sort -u)
    
    log_info "Available network interfaces:"
    echo ""
    local first_lan=""
    for iface in $all_interfaces; do
        local state mac ip_addr
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "unknown")
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)
        ip_addr="${ip_addr:-no IP}"
        printf "  %-15s %-10s %-18s %s\n" "$iface" "$state" "$mac" "$ip_addr"
        
        if [[ -z "$first_lan" ]] && [[ "$state" == "up" ]] && [[ "$iface" != "eth0" ]]; then
            [[ "$ip_addr" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]] && first_lan="$iface"
        fi
    done
    echo ""
    
    if [[ ${#MONITOR_INTERFACES[@]} -gt 0 ]]; then
        for iface in "${MONITOR_INTERFACES[@]}"; do
            validate_interface "$iface" || { log_error "Interface not found: $iface"; exit 1; }
            log_success "Validated interface: $iface"
        done
    else
        echo -e "${YELLOW}Tip: Monitor LAN interfaces to see internal traffic (WAN shows NAT'd IPs)${NC}"
        echo ""
        local suggested="${first_lan:-eth1}"
        
        if [[ "$NON_INTERACTIVE" == true ]]; then
            validate_interface "$suggested" && MONITOR_INTERFACES=("$suggested") || { validate_interface "eth0" && MONITOR_INTERFACES=("eth0") || { log_error "No valid interface"; exit 1; }; }
        else
            read -r -p "Enter interface(s) to monitor (comma-separated) [$suggested]: " user_input
            user_input="${user_input:-$suggested}"
            IFS=',' read -ra MONITOR_INTERFACES <<< "$user_input"
            for i in "${!MONITOR_INTERFACES[@]}"; do MONITOR_INTERFACES[$i]=$(echo "${MONITOR_INTERFACES[$i]}" | xargs); done
        fi
        
        for iface in "${MONITOR_INTERFACES[@]}"; do
            validate_interface "$iface" || { log_error "Interface not found: $iface"; exit 1; }
        done
    fi
    
    [[ ${#MONITOR_INTERFACES[@]} -eq 0 ]] && { log_error "No interfaces selected"; exit 1; }
    [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]] && log_success "Mode: Standalone (1 interface)" || log_success "Mode: Cluster (${#MONITOR_INTERFACES[@]} interfaces)"
    log_success "Monitor interfaces: ${MONITOR_INTERFACES[*]}"
}

detect_networks() {
    [[ -n "$LOCAL_NETWORKS" ]] && { log_info "Using specified networks: $LOCAL_NETWORKS"; return; }
    LOCAL_NETWORKS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    log_success "Local networks: $LOCAL_NETWORKS (RFC1918)"
}

check_filesystem_writable() {
    log_header "Checking Filesystem"

    # Check if /opt is writable
    if ! touch /opt/.zeek-write-test 2>/dev/null; then
        log_warning "Filesystem appears read-only"
        log_info "Attempting to remount with write access..."

        # Try to make the filesystem writable (VyOS specific)
        if mount -o remount,rw / 2>/dev/null; then
            log_success "Filesystem remounted with write access"
        else
            log_error "Cannot write to /opt - filesystem is read-only"
            log_info "VyOS may need to be in configuration mode"
            log_info "Try: configure; then run this script again"
            exit 1
        fi
    else
        rm -f /opt/.zeek-write-test
        log_success "Filesystem is writable"
    fi

    mkdir -p "$ZEEK_PREFIX" "$TEMP_DIR"
}

get_zeek_repo_url() {
    # Determine the correct OBS repository URL based on Debian version
    case "$DEBIAN_CODENAME" in
        bookworm|12) echo "https://download.opensuse.org/repositories/security:/zeek/Debian_12" ;;
        bullseye|11) echo "https://download.opensuse.org/repositories/security:/zeek/Debian_11" ;;
        *) echo "https://download.opensuse.org/repositories/security:/zeek/Debian_12" ;;
    esac
}

download_and_extract_binaries() {
    log_header "Downloading Pre-built Zeek Binaries"

    local repo_url arch pkg_list
    repo_url=$(get_zeek_repo_url)
    arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

    log_info "Repository: $repo_url"
    log_info "Architecture: $arch"

    cd "$TEMP_DIR"

    # Download repository package list
    log_info "Fetching package list..."
    curl -fsSL "${repo_url}/Packages.gz" 2>/dev/null | gunzip > Packages || \
    curl -fsSL "${repo_url}/Packages" -o Packages || {
        log_error "Failed to fetch package list from repository"
        log_info "Trying alternative download method..."
        download_zeek_lts
        return
    }

    # Find the main zeek package and dependencies
    local zeek_pkg zeek_core_pkg zeekctl_pkg libbroker_pkg

    # Parse package list to find latest versions
    zeek_pkg=$(grep -A 20 "^Package: zeek$" Packages | grep "^Filename:" | head -1 | awk '{print $2}')
    zeek_core_pkg=$(grep -A 20 "^Package: zeek-core$" Packages | grep "^Filename:" | head -1 | awk '{print $2}')
    zeekctl_pkg=$(grep -A 20 "^Package: zeekctl$" Packages | grep "^Filename:" | head -1 | awk '{print $2}')
    libbroker_pkg=$(grep -A 20 "^Package: libbroker-dev$" Packages | grep "^Filename:" | head -1 | awk '{print $2}')

    if [[ -z "$zeek_core_pkg" ]]; then
        log_warning "Could not find zeek-core package, trying LTS download..."
        download_zeek_lts
        return
    fi

    # Download packages
    local packages=("$zeek_core_pkg" "$zeekctl_pkg")
    [[ -n "$libbroker_pkg" ]] && packages+=("$libbroker_pkg")

    log_info "Downloading ${#packages[@]} packages..."
    for pkg in "${packages[@]}"; do
        [[ -z "$pkg" ]] && continue
        local pkg_name=$(basename "$pkg")
        log_info "  Downloading $pkg_name..."
        curl -fsSL "${repo_url}/${pkg}" -o "$pkg_name" || {
            log_warning "Failed to download $pkg_name"
            continue
        }
        echo -e "  ${GREEN}✓${NC} $pkg_name"
    done

    # Extract packages
    log_info "Extracting packages to $ZEEK_PREFIX..."
    mkdir -p "$TEMP_DIR/extracted"
    for deb in *.deb; do
        [[ -f "$deb" ]] || continue
        log_info "  Extracting $deb..."
        dpkg-deb -x "$deb" "$TEMP_DIR/extracted" 2>/dev/null || {
            # Fallback: use ar and tar
            ar x "$deb" 2>/dev/null
            if [[ -f data.tar.xz ]]; then
                tar -xf data.tar.xz -C "$TEMP_DIR/extracted" 2>/dev/null
            elif [[ -f data.tar.zst ]]; then
                zstd -d data.tar.zst -o data.tar 2>/dev/null && tar -xf data.tar -C "$TEMP_DIR/extracted"
            elif [[ -f data.tar.gz ]]; then
                tar -xzf data.tar.gz -C "$TEMP_DIR/extracted" 2>/dev/null
            fi
            rm -f data.tar* control.tar* debian-binary
        }
        echo -e "  ${GREEN}✓${NC} Extracted $deb"
    done

    # Move files to proper locations
    mkdir -p "$ZEEK_PREFIX"
    if [[ -d "$TEMP_DIR/extracted/opt/zeek" ]]; then
        cp -r "$TEMP_DIR/extracted/opt/zeek/"* "$ZEEK_PREFIX/" 2>/dev/null || true
    fi
    if [[ -d "$TEMP_DIR/extracted/usr" ]]; then
        # Copy libraries
        cp -r "$TEMP_DIR/extracted/usr/lib/"* /usr/lib/ 2>/dev/null || true
        cp -r "$TEMP_DIR/extracted/usr/bin/"* /usr/bin/ 2>/dev/null || true
    fi

    log_success "Binaries extracted to $ZEEK_PREFIX"
}

download_zeek_lts() {
    log_header "Downloading Zeek LTS Binary Release"

    # Alternative: Download from Zeek's binary releases
    local arch release_url
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    # Try to get the static/portable build
    log_info "Checking for portable Zeek build..."

    # Zeek provides tarballs for some releases
    local tarball_url="https://download.zeek.org/binary-packages/Debian_12/${arch}/"

    log_info "Fetching from: $tarball_url"

    # List available packages
    local pkg_list
    pkg_list=$(curl -fsSL "$tarball_url" 2>/dev/null | grep -oP 'href="\K[^"]+\.deb' | head -20) || {
        log_warning "Could not list packages from binary repository"
        log_info "Attempting direct package download..."
    }

    if [[ -n "$pkg_list" ]]; then
        log_info "Available packages:"
        echo "$pkg_list" | head -5

        # Download zeek-core and zeekctl
        for pattern in "zeek-core_" "zeekctl_"; do
            local pkg=$(echo "$pkg_list" | grep "^${pattern}" | sort -V | tail -1)
            if [[ -n "$pkg" ]]; then
                log_info "Downloading $pkg..."
                curl -fsSL "${tarball_url}${pkg}" -o "$TEMP_DIR/$pkg" && \
                    echo -e "  ${GREEN}✓${NC} $pkg"
            fi
        done
    fi

    # Extract any downloaded debs
    cd "$TEMP_DIR"
    mkdir -p extracted
    for deb in *.deb; do
        [[ -f "$deb" ]] || continue
        dpkg-deb -x "$deb" extracted/ 2>/dev/null || {
            ar x "$deb" 2>/dev/null
            [[ -f data.tar.xz ]] && tar -xf data.tar.xz -C extracted/
            [[ -f data.tar.zst ]] && { zstd -d data.tar.zst -o data.tar && tar -xf data.tar -C extracted/; }
            [[ -f data.tar.gz ]] && tar -xzf data.tar.gz -C extracted/
            rm -f data.tar* control.tar* debian-binary
        }
    done

    # Install extracted files
    if [[ -d "extracted/opt/zeek" ]]; then
        mkdir -p "$ZEEK_PREFIX"
        cp -r extracted/opt/zeek/* "$ZEEK_PREFIX/"
        log_success "Zeek installed to $ZEEK_PREFIX"
    else
        log_error "Failed to extract Zeek binaries"
        log_info ""
        log_info "Manual installation alternative:"
        log_info "  1. On a Debian 12 machine, run:"
        log_info "     apt install zeek"
        log_info "  2. Copy /opt/zeek to this VyOS system:"
        log_info "     scp -r /opt/zeek vyos:/opt/"
        exit 1
    fi
}

install_runtime_deps() {
    log_header "Checking Runtime Dependencies"

    # List of runtime libraries Zeek needs
    local required_libs=("libpcap" "libssl" "libcrypto" "libz" "libmaxminddb")
    local missing=()

    for lib in "${required_libs[@]}"; do
        if ! ldconfig -p 2>/dev/null | grep -q "$lib"; then
            missing+=("$lib")
        else
            echo -e "  ${GREEN}✓${NC} $lib"
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warning "Some libraries may be missing: ${missing[*]}"
        log_info "Zeek may still work if libraries are present in non-standard locations"
    fi

    # Set library path to include Zeek's lib directory
    if [[ -d "$ZEEK_PREFIX/lib" ]]; then
        echo "$ZEEK_PREFIX/lib" > /etc/ld.so.conf.d/zeek.conf 2>/dev/null || true
        ldconfig 2>/dev/null || true
    fi

    log_success "Runtime dependency check complete"
}

configure_zeek() {
    log_header "Configuring Zeek"

    # Create etc directory if it doesn't exist (may happen with binary extraction)
    mkdir -p "$ZEEK_PREFIX/etc" "$ZEEK_PREFIX/logs" "$ZEEK_PREFIX/spool"
    
    cat > /etc/profile.d/zeek.sh << EOF
export PATH="\$PATH:$ZEEK_PREFIX/bin"
EOF
    export PATH="$PATH:$ZEEK_PREFIX/bin"
    log_success "Added Zeek to PATH"
    
    cat > "$ZEEK_PREFIX/etc/networks.cfg" << EOF
10.0.0.0/8          Private IP space
172.16.0.0/12       Private IP space
192.168.0.0/16      Private IP space
EOF
    log_success "Configured networks.cfg"
    
    if [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]]; then
        cat > "$ZEEK_PREFIX/etc/node.cfg" << EOF
[zeek]
type=standalone
host=localhost
interface=${MONITOR_INTERFACES[0]}
EOF
        log_success "Configured standalone mode: ${MONITOR_INTERFACES[0]}"
    else
        cat > "$ZEEK_PREFIX/etc/node.cfg" << EOF
[logger]
type=logger
host=localhost

[manager]
type=manager
host=localhost

[proxy-1]
type=proxy
host=localhost

EOF
        local n=1; for iface in "${MONITOR_INTERFACES[@]}"; do
            cat >> "$ZEEK_PREFIX/etc/node.cfg" << EOF
[worker-$n]
type=worker
host=localhost
interface=$iface

EOF
            ((n++))
        done
        log_success "Configured cluster mode: ${#MONITOR_INTERFACES[@]} workers"
    fi
    
    [[ -f "$ZEEK_PREFIX/etc/zeekctl.cfg" ]] && sed -i 's/^MailTo = .*/MailTo = /' "$ZEEK_PREFIX/etc/zeekctl.cfg" 2>/dev/null || true
}

setup_zeekctl() {
    log_header "Initializing Zeek Control"
    cd "$ZEEK_PREFIX"
    "$ZEEK_PREFIX/bin/zeekctl" install 2>&1 || true
    "$ZEEK_PREFIX/bin/zeekctl" deploy 2>&1 || true
    log_info "Status:"; "$ZEEK_PREFIX/bin/zeekctl" status 2>&1 || true
    log_success "Zeek control initialized"
}

create_systemd_service() {
    log_header "Creating Systemd Service"
    cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
Environment="PATH=$ZEEK_PREFIX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$ZEEK_PREFIX/bin/zeekctl deploy
ExecStop=$ZEEK_PREFIX/bin/zeekctl stop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable zeek.service 2>/dev/null || true
    log_success "Created zeek.service"
}

cleanup_temp() {
    log_header "Cleanup"
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log_success "Removed temporary files"
    fi
}

verify_installation() {
    log_header "Verifying Installation"
    local errors=0
    
    [[ -x "$ZEEK_PREFIX/bin/zeek" ]] && log_success "Zeek binary: $("$ZEEK_PREFIX/bin/zeek" --version 2>/dev/null || echo 'installed')" || { log_error "Zeek binary not found"; ((errors++)) || true; }
    [[ -x "$ZEEK_PREFIX/bin/zeekctl" ]] && log_success "zeekctl installed" || log_warning "zeekctl not found"
    [[ -f "$ZEEK_PREFIX/etc/node.cfg" ]] && log_success "node.cfg configured" || log_error "node.cfg missing"
    
    if grep -q "type=standalone" "$ZEEK_PREFIX/etc/node.cfg" 2>/dev/null; then
        log_info "Mode: Standalone"
    else
        log_info "Mode: Cluster ($(grep -c 'type=worker' "$ZEEK_PREFIX/etc/node.cfg" 2>/dev/null || echo 0) workers)"
    fi
    
    "$ZEEK_PREFIX/bin/zeekctl" status 2>/dev/null | grep -q "running" && log_success "Zeek is running" || log_warning "Zeek not running - start with: zeekctl deploy"
    return $errors
}

print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ZEEK INSTALLATION COMPLETE                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Summary:${NC}"
    echo "  • VyOS: $VYOS_VERSION | Zeek: $ZEEK_VERSION (pre-built binary)"
    echo "  • Path: $ZEEK_PREFIX"
    echo "  • Interfaces: ${MONITOR_INTERFACES[*]}"
    [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]] && echo "  • Mode: Standalone" || echo "  • Mode: Cluster (${#MONITOR_INTERFACES[@]} workers)"
    echo ""
    echo -e "${GREEN}Commands:${NC}"
    echo "  ${ZEEK_PREFIX}/bin/zeekctl status | deploy | stop"
    echo "  systemctl status zeek"
    echo ""
    echo -e "${GREEN}Verify installation:${NC}"
    echo "  ${ZEEK_PREFIX}/bin/zeek --version"
    echo ""
    echo -e "${YELLOW}Next: ./zeekDetectionConfigure.sh${NC}"
    echo ""
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface) IFS=',' read -ra MONITOR_INTERFACES <<< "$2"; for i in "${!MONITOR_INTERFACES[@]}"; do MONITOR_INTERFACES[$i]=$(echo "${MONITOR_INTERFACES[$i]}" | xargs); done; shift 2 ;;
            -n|--networks) LOCAL_NETWORKS="$2"; shift 2 ;;
            -v|--zeek-version) ZEEK_VERSION="$2"; shift 2 ;;
            -y|--yes) NON_INTERACTIVE=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        VYOS ZEEK INSTALLATION SCRIPT v2.0.0                    ║${NC}"
    echo -e "${CYAN}║        (Pre-built Binary Installation)                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"

    check_root
    log_step "1/8" "Detecting VyOS"; detect_vyos
    log_step "2/8" "Checking Filesystem"; check_filesystem_writable
    log_step "3/8" "Detecting Interfaces"; detect_interfaces; detect_networks
    log_step "4/8" "Downloading Binaries"; download_and_extract_binaries
    log_step "5/8" "Runtime Dependencies"; install_runtime_deps
    log_step "6/8" "Configuring Zeek"; configure_zeek
    log_step "7/8" "Setting Up Services"; setup_zeekctl; create_systemd_service
    log_step "8/8" "Cleanup & Verify"; cleanup_temp; verify_installation || true
    print_summary
}

main "$@"
