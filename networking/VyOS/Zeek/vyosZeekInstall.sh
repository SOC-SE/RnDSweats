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
#    6. Installs pip, zkg (Zeek Package Manager), and websockets
#    7. Installs JA3 package for TLS fingerprinting
#
#  Usage: ./install-zeek-vyos.sh [options]
#
#  Options:
#    -i, --interface IFACE   Network interface(s) to monitor (comma-separated)
#    -n, --networks CIDR     Local networks (comma-separated, auto-detected from interface)
#                            RFC1918 NOT assumed - only your actual subnets are marked local
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
  -n, --networks CIDR     Local networks, comma-separated (default: auto-detect)
                          Examples: -n "10.50.0.0/16" OR -n "192.168.1.0/24,10.0.0.0/8"
                          Use -n "" for empty (treat all traffic as external)
  -v, --zeek-version VER  Zeek major version (default: 7.0)
  -y, --yes               Non-interactive mode
  -h, --help              Show this help message

Note: RFC1918 ranges are NOT assumed to be local. In competition environments,
      attackers may use private IP ranges. Only your actual network is marked local.

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

calculate_network_address() {
    # Convert IP/CIDR to network address (e.g., 172.16.101.1/24 -> 172.16.101.0/24)
    local ip_cidr="$1"
    local ip="${ip_cidr%/*}"
    local prefix="${ip_cidr#*/}"

    # Split IP into octets
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    # Calculate netmask from prefix
    local mask=$((0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF))
    local m1=$(( (mask >> 24) & 255 ))
    local m2=$(( (mask >> 16) & 255 ))
    local m3=$(( (mask >> 8) & 255 ))
    local m4=$(( mask & 255 ))

    # Apply netmask to get network address
    local n1=$((o1 & m1))
    local n2=$((o2 & m2))
    local n3=$((o3 & m3))
    local n4=$((o4 & m4))

    echo "${n1}.${n2}.${n3}.${n4}/${prefix}"
}

detect_networks() {
    log_header "Configuring Local Networks"

    # Check if user specified networks via -n flag
    if [[ -n "$LOCAL_NETWORKS" ]]; then
        log_success "Using specified networks: $LOCAL_NETWORKS"
        return
    fi

    # Default networks for the lab environment
    # User can override with -n flag or interactively
    local default_networks="172.16.101.0/24,172.16.102.0/24,172.20.240.0/24,172.20.242.0/24"
    LOCAL_NETWORKS="$default_networks"
    log_info "Using default local networks:"
    log_info "  • 172.16.101.0/24"
    log_info "  • 172.16.102.0/24"
    log_info "  • 172.20.240.0/24"
    log_info "  • 172.20.242.0/24"

    # Prompt for confirmation/override in interactive mode
    if [[ "$NON_INTERACTIVE" != true ]]; then
        echo ""
        echo -e "${YELLOW}Override with your networks or press Enter to accept defaults${NC}"
        read -r -p "Local networks [$LOCAL_NETWORKS]: " user_nets
        if [[ -n "$user_nets" ]]; then
            LOCAL_NETWORKS="$user_nets"
            log_success "Using custom networks: $LOCAL_NETWORKS"
        else
            log_success "Using default networks"
        fi
    fi
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

    # Detect architecture properly
    local machine_arch
    machine_arch=$(uname -m)
    case "$machine_arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="armhf" ;;
        i686)    arch="i386" ;;
        *)       arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64") ;;
    esac

    log_info "Repository: $repo_url"
    log_info "System architecture: $machine_arch -> $arch"

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

    # Find packages matching our architecture
    # Parse Packages file to extract package info for correct architecture
    local zeek_pkg zeek_core_pkg zeekctl_pkg libbroker_pkg

    # Function to find package filename for specific arch
    find_pkg_for_arch() {
        local pkg_name="$1"
        local target_arch="$2"
        awk -v pkg="$pkg_name" -v arch="$target_arch" '
            /^Package:/ { current_pkg = $2; current_arch = ""; filename = "" }
            /^Architecture:/ { current_arch = $2 }
            /^Filename:/ { filename = $2 }
            /^$/ {
                if (current_pkg == pkg && (current_arch == arch || current_arch == "all"))
                    print filename
            }
        ' Packages | tail -1
    }

    zeek_core_pkg=$(find_pkg_for_arch "zeek-core" "$arch")
    zeekctl_pkg=$(find_pkg_for_arch "zeekctl" "$arch")
    libbroker_pkg=$(find_pkg_for_arch "libbroker-dev" "$arch")

    if [[ -z "$zeek_core_pkg" ]]; then
        log_warning "Could not find zeek-core package, trying LTS download..."
        download_zeek_lts
        return
    fi

    # Download packages
    local packages=("$zeek_core_pkg" "$zeekctl_pkg")
    [[ -n "$libbroker_pkg" ]] && packages+=("$libbroker_pkg")

    log_info "Downloading ${#packages[@]} packages..."
    local download_failed=false
    for pkg in "${packages[@]}"; do
        [[ -z "$pkg" ]] && continue
        local pkg_name=$(basename "$pkg")
        log_info "  Downloading $pkg_name..."
        curl -fsSL --retry 3 --retry-delay 5 "${repo_url}/${pkg}" -o "$pkg_name" || {
            log_warning "Failed to download $pkg_name"
            download_failed=true
            continue
        }
        echo -e "  ${GREEN}✓${NC} $pkg_name"
    done

    # If zeek-core didn't download, fall back to LTS method
    if [[ "$download_failed" == true ]] && ! ls zeek-core_*.deb &>/dev/null; then
        log_warning "Critical package zeek-core failed to download, trying LTS fallback..."
        download_zeek_lts
        return
    fi

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

    # Verify critical binary was extracted
    if [[ ! -x "$ZEEK_PREFIX/bin/zeek" ]]; then
        log_warning "zeek binary not found after extraction, trying LTS fallback..."
        download_zeek_lts
        return
    fi

    log_success "Binaries extracted to $ZEEK_PREFIX"
}

download_zeek_lts() {
    log_header "Downloading Zeek LTS Binary Release"

    # Detect architecture properly
    local machine_arch arch
    machine_arch=$(uname -m)
    case "$machine_arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $machine_arch"; exit 1 ;;
    esac

    log_info "Target architecture: $machine_arch -> $arch"

    # Try OBS repository with architecture-specific path
    local obs_url="https://download.opensuse.org/repositories/security:/zeek/Debian_12/${arch}/"

    log_info "Fetching from OBS: $obs_url"

    # List available packages
    local pkg_list
    pkg_list=$(curl -fsSL "$obs_url" 2>/dev/null | grep -oP 'href="\K[^"]+\.deb' | head -20) || {
        log_warning "Could not list packages from OBS repository"
    }

    if [[ -n "$pkg_list" ]]; then
        log_info "Available packages for $arch:"
        echo "$pkg_list" | grep -E "zeek-core|zeekctl" | head -5

        # Download zeek-core and zeekctl - filter for correct arch in filename
        for pattern in "zeek-core_" "zeekctl_"; do
            # Filter packages that match our architecture (amd64 or arm64 in filename)
            local pkg=$(echo "$pkg_list" | grep "^${pattern}" | grep "_${arch}\." | sort -V | tail -1)
            if [[ -z "$pkg" ]]; then
                # Try without arch in filename
                pkg=$(echo "$pkg_list" | grep "^${pattern}" | sort -V | tail -1)
            fi
            if [[ -n "$pkg" ]]; then
                log_info "Downloading $pkg..."
                curl -fsSL --retry 3 --retry-delay 5 "${obs_url}${pkg}" -o "$TEMP_DIR/$pkg" && \
                    echo -e "  ${GREEN}✓${NC} $pkg"
            fi
        done
    fi

    # Fallback: try Zeek's own binary download site
    if ! ls "$TEMP_DIR"/zeek-core_*.deb &>/dev/null; then
        local zeek_url="https://download.zeek.org/binary-packages/Debian_12/${arch}/"
        log_info "Trying Zeek download site: $zeek_url"

        pkg_list=$(curl -fsSL "$zeek_url" 2>/dev/null | grep -oP 'href="\K[^"]+\.deb' | head -20) || true

        if [[ -n "$pkg_list" ]]; then
            for pattern in "zeek-core_" "zeekctl_"; do
                local pkg=$(echo "$pkg_list" | grep "^${pattern}" | grep "_${arch}\." | sort -V | tail -1)
                [[ -z "$pkg" ]] && pkg=$(echo "$pkg_list" | grep "^${pattern}" | sort -V | tail -1)
                if [[ -n "$pkg" ]]; then
                    log_info "Downloading $pkg..."
                    curl -fsSL --retry 3 --retry-delay 5 "${zeek_url}${pkg}" -o "$TEMP_DIR/$pkg" && \
                        echo -e "  ${GREEN}✓${NC} $pkg"
                fi
            done
        fi
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
    
    # Configure networks.cfg based on detected/specified networks
    if [[ -n "$LOCAL_NETWORKS" ]]; then
        # Write each network on its own line
        > "$ZEEK_PREFIX/etc/networks.cfg"
        IFS=',' read -ra nets <<< "$LOCAL_NETWORKS"
        for net in "${nets[@]}"; do
            net=$(echo "$net" | xargs)  # trim whitespace
            echo "$net    Local network" >> "$ZEEK_PREFIX/etc/networks.cfg"
        done
        log_success "Configured networks.cfg with: $LOCAL_NETWORKS"
    else
        # Empty networks.cfg - all traffic treated as external
        > "$ZEEK_PREFIX/etc/networks.cfg"
        log_info "networks.cfg left empty (all traffic treated as external)"
    fi
    
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

    # Add -C flag to ignore checksums (NIC offloading causes invalid checksums on loopback/NAT traffic)
    # Without this, client TLS fingerprints (JA3/JA4) may not be captured correctly
    if [[ -f "$ZEEK_PREFIX/etc/zeekctl.cfg" ]] && ! grep -q "^ZeekArgs" "$ZEEK_PREFIX/etc/zeekctl.cfg"; then
        echo "ZeekArgs = -C" >> "$ZEEK_PREFIX/etc/zeekctl.cfg"
        log_info "Added ZeekArgs = -C to ignore checksums"
    fi
}

setup_zeekctl() {
    log_header "Initializing Zeek Control"
    cd "$ZEEK_PREFIX"
    "$ZEEK_PREFIX/bin/zeekctl" install 2>&1 || true
    "$ZEEK_PREFIX/bin/zeekctl" deploy 2>&1 || true
    log_info "Status:"; "$ZEEK_PREFIX/bin/zeekctl" status 2>&1 || true
    log_success "Zeek control initialized"
}

configure_path() {
    log_header "Configuring System PATH"

    # Create system-wide profile.d script for persistent PATH
    # This ensures zeek, zeekctl, zkg, pip3 are available to all users after login
    cat > /etc/profile.d/zeek.sh << 'PATHEOF'
# Zeek Network Security Monitor - PATH configuration
# Added by VyOS Zeek installer

# Zeek binaries
if [ -d "/opt/zeek/bin" ]; then
    export PATH="/opt/zeek/bin:$PATH"
fi

# User-installed pip packages (zkg, etc)
if [ -d "$HOME/.local/bin" ]; then
    export PATH="$HOME/.local/bin:$PATH"
fi
PATHEOF
    chmod 644 /etc/profile.d/zeek.sh
    log_success "Created /etc/profile.d/zeek.sh for persistent PATH"

    # Update current session PATH immediately
    export PATH="/opt/zeek/bin:$HOME/.local/bin:$PATH"
    log_info "Updated current session PATH"

    # Also add to root's .bashrc for interactive shells
    if [[ ! -f ~/.bashrc ]] || ! grep -q '/opt/zeek/bin' ~/.bashrc 2>/dev/null; then
        echo '' >> ~/.bashrc
        echo '# Zeek and pip user packages' >> ~/.bashrc
        echo 'export PATH="/opt/zeek/bin:$HOME/.local/bin:$PATH"' >> ~/.bashrc
        log_info "Added PATH to ~/.bashrc"
    fi

    log_success "PATH configured - zeek, zeekctl, zkg, pip3 will be available"
}

install_zeek_packages() {
    log_header "Installing Zeek Package Manager (zkg) and JA3"

    # Install pip if not available (VyOS doesn't have it by default)
    if ! command -v pip3 &>/dev/null; then
        log_info "Installing pip..."
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
        python3 /tmp/get-pip.py --user --break-system-packages 2>/dev/null || \
        python3 /tmp/get-pip.py --user
        rm -f /tmp/get-pip.py

        # Ensure PATH is set for pip3 to be found
        export PATH="$HOME/.local/bin:$PATH"
        hash -r  # Refresh command hash table
        log_success "pip installed"
    else
        log_success "pip already available"
    fi

    # Install zkg and websockets
    log_info "Installing zkg and websockets..."
    pip3 install zkg --break-system-packages 2>/dev/null || \
    pip3 install --user zkg --break-system-packages 2>/dev/null || \
    pip3 install --user zkg || {
        log_warning "Could not install zkg via pip"
        return 1
    }
    log_success "zkg installed"

    pip3 install websockets --break-system-packages 2>/dev/null || \
    pip3 install --user websockets --break-system-packages 2>/dev/null || \
    pip3 install --user websockets || true
    log_success "websockets installed"

    # Configure zkg
    log_info "Configuring zkg..."
    "$HOME/.local/bin/zkg" autoconfig 2>/dev/null || \
    zkg autoconfig 2>/dev/null || {
        log_warning "zkg autoconfig failed - may need manual configuration"
    }

    # Install JA3 for TLS fingerprinting (legacy, broad coverage)
    log_info "Installing JA3 package for TLS fingerprinting..."
    "$HOME/.local/bin/zkg" install zeek/salesforce/ja3 --force 2>/dev/null || \
    zkg install zeek/salesforce/ja3 --force 2>/dev/null || {
        log_warning "Could not install JA3 via zkg"
    }

    # Install JA4+ suite (modern TLS 1.3 aware fingerprinting)
    # Includes: JA4, JA4S, JA4H, JA4L, JA4X, JA4SSH
    log_info "Installing JA4+ package (modern TLS fingerprinting)..."
    "$HOME/.local/bin/zkg" install zeek/foxio/ja4 --force 2>/dev/null || \
    zkg install zeek/foxio/ja4 --force 2>/dev/null || {
        log_warning "Could not install JA4 via zkg"
    }

    # Install HASSH for SSH fingerprinting
    log_info "Installing HASSH package for SSH fingerprinting..."
    "$HOME/.local/bin/zkg" install zeek/corelight/hassh --force 2>/dev/null || \
    zkg install zeek/corelight/hassh --force 2>/dev/null || {
        log_warning "Could not install HASSH via zkg"
    }

    # Install BZAR for lateral movement detection
    log_info "Installing MITRE BZAR package..."
    "$HOME/.local/bin/zkg" install zeek/mitre-attack/bzar --force 2>/dev/null || \
    zkg install zeek/mitre-attack/bzar --force 2>/dev/null || {
        log_warning "Could not install BZAR via zkg"
    }

    # Deploy changes
    log_info "Deploying Zeek configuration..."
    "$ZEEK_PREFIX/bin/zeekctl" deploy 2>&1 || true
    log_success "Zeek packages installed and deployed"
}

create_systemd_service() {
    log_header "Creating Systemd Service"
    cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
Environment="PATH=$ZEEK_PREFIX/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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
    [[ -n "$LOCAL_NETWORKS" ]] && echo "  • Local networks: $LOCAL_NETWORKS" || echo "  • Local networks: (none - all traffic external)"
    command -v zkg &>/dev/null && echo "  • zkg: installed" || echo "  • zkg: not found"

    # Check fingerprinting packages
    echo ""
    echo -e "${GREEN}Fingerprinting Packages:${NC}"
    if zkg list 2>/dev/null | grep -q "ja3"; then
        echo "  • JA3:   installed (TLS fingerprinting)"
    else
        echo "  • JA3:   not installed"
    fi
    if zkg list 2>/dev/null | grep -q "ja4"; then
        echo "  • JA4+:  installed (modern TLS fingerprinting)"
    else
        echo "  • JA4+:  not installed"
    fi
    if zkg list 2>/dev/null | grep -q "hassh"; then
        echo "  • HASSH: installed (SSH fingerprinting)"
    else
        echo "  • HASSH: not installed"
    fi
    if zkg list 2>/dev/null | grep -q "bzar"; then
        echo "  • BZAR:  installed (lateral movement)"
    else
        echo "  • BZAR:  not installed"
    fi
    echo ""
    echo -e "${GREEN}PATH Configuration:${NC}"
    echo "  • System-wide: /etc/profile.d/zeek.sh (automatic on next login)"
    echo "  • To apply NOW: source /etc/profile.d/zeek.sh"
    echo ""
    echo -e "${GREEN}Commands (after sourcing PATH):${NC}"
    echo "  zeekctl status | deploy | stop"
    echo "  zeek --version"
    echo "  zkg list"
    echo "  systemctl status zeek"
    echo ""
    echo -e "${YELLOW}Apply PATH now, then run detection config:${NC}"
    echo "  source /etc/profile.d/zeek.sh"
    echo "  ./zeekDetectionConfigure.sh"
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
    log_step "1/10" "Detecting VyOS"; detect_vyos
    log_step "2/10" "Checking Filesystem"; check_filesystem_writable
    log_step "3/10" "Detecting Interfaces"; detect_interfaces; detect_networks
    log_step "4/10" "Downloading Binaries"; download_and_extract_binaries
    # Verify Zeek binary exists before continuing
    if [[ ! -x "$ZEEK_PREFIX/bin/zeek" ]]; then
        log_error "Zeek binary not found at $ZEEK_PREFIX/bin/zeek after download"
        log_error "All download methods failed. This is usually caused by:"
        log_error "  - Temporary OBS repository outage (503 errors)"
        log_error "  - Network connectivity issues"
        log_info "Try running the script again, or manually download Zeek packages:"
        log_info "  apt install zeek  (on a Debian 12 machine)"
        log_info "  scp -r /opt/zeek vyos:/opt/"
        exit 1
    fi
    log_step "5/10" "Runtime Dependencies"; install_runtime_deps
    log_step "6/10" "Configuring PATH"; configure_path
    log_step "7/10" "Configuring Zeek"; configure_zeek
    log_step "8/10" "Setting Up Services"; setup_zeekctl; create_systemd_service
    log_step "9/10" "Installing Packages (pip/zkg/JA3)"; install_zeek_packages
    log_step "10/10" "Cleanup & Verify"; cleanup_temp; verify_installation || true
    print_summary
}

main "$@"
