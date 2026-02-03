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
#  Version: 1.1.0
#
#  Installs Zeek Network Security Monitor on VyOS by:
#    1. Configuring Debian repositories (VyOS is Debian-based)
#    2. Installing build dependencies
#    3. Compiling Zeek from source
#    4. Configuring Zeek for your network interfaces
#    5. Setting up zeekctl for management
#
#  Usage: ./install-zeek-vyos.sh [options]
#
#  Options:
#    -i, --interface IFACE   Network interface(s) to monitor (comma-separated)
#    -n, --networks CIDR     Local networks (comma-separated, default: auto-detect)
#    -v, --zeek-version VER  Zeek version to install (default: 7.0.4)
#    -j, --jobs N            Parallel compile jobs (default: auto)
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
ZEEK_VERSION="7.0.4"
COMPILE_JOBS=""
NON_INTERACTIVE=false
ZEEK_PREFIX="/opt/zeek"
VYOS_VERSION=""
DEBIAN_VERSION=""
DEBIAN_CODENAME=""

log_header() { echo ""; echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${MAGENTA}[STEP $1]${NC} $2"; }

show_help() {
    cat << 'EOF'
VyOS Zeek Installation Script

Installs Zeek Network Security Monitor on VyOS by compiling from source.

Usage: ./install-zeek-vyos.sh [options]

Options:
  -i, --interface IFACE   Network interface(s) to monitor, comma-separated
                          Examples: -i eth1  OR  -i "eth1,eth2,eth3"
  -n, --networks CIDR     Local networks, comma-separated (default: RFC1918)
  -v, --zeek-version VER  Zeek version to install (default: 7.0.4)
  -j, --jobs N            Parallel compile jobs (default: nproc-1)
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

setup_debian_repos() {
    log_header "Configuring Debian Repositories"
    log_warning "VyOS limits package installation - enabling Debian repos temporarily"
    
    [[ "$NON_INTERACTIVE" != true ]] && ! prompt_yes_no "Continue? [Y/n]" "y" && { log_error "Aborted"; exit 1; }
    
    [[ -f /etc/apt/sources.list ]] && cp /etc/apt/sources.list "/etc/apt/sources.list.backup.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    
    cat > /etc/apt/sources.list.d/debian-zeek-build.list << EOF
deb http://deb.debian.org/debian ${DEBIAN_CODENAME} main contrib
deb http://deb.debian.org/debian ${DEBIAN_CODENAME}-updates main contrib
deb http://security.debian.org/debian-security ${DEBIAN_CODENAME}-security main contrib
EOF
    log_success "Created Debian repository config"
    
    apt-get update -qq 2>&1 | grep -v "^W:" || true
    log_success "Repository configuration complete"
}

install_build_deps() {
    log_header "Installing Build Dependencies"
    
    local deps=(build-essential cmake make gcc g++ flex bison git libpcap-dev libssl-dev python3 python3-dev python3-pip swig zlib1g-dev libmaxminddb-dev)
    local optional=(libkrb5-dev libgoogle-perftools-dev)
    
    log_info "Installing ${#deps[@]} packages..."
    for pkg in "${deps[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            apt-get install -y -qq "$pkg" 2>/dev/null && echo -e "  ${GREEN}✓${NC} $pkg" || echo -e "  ${YELLOW}!${NC} $pkg (failed)"
        else
            echo -e "  ${GREEN}✓${NC} $pkg (installed)"
        fi
    done
    
    for pkg in "${optional[@]}"; do apt-get install -y -qq "$pkg" 2>/dev/null || true; done
    
    for pkg in cmake gcc g++ libpcap-dev libssl-dev python3; do
        dpkg -s "$pkg" &>/dev/null || { log_error "Critical package missing: $pkg"; exit 1; }
    done
    log_success "Build dependencies installed"
}

download_zeek() {
    log_header "Downloading Zeek $ZEEK_VERSION"
    
    local src_dir="/usr/local/src" zeek_dir="/usr/local/src/zeek-$ZEEK_VERSION"
    mkdir -p "$src_dir"; cd "$src_dir"
    
    if [[ -d "$zeek_dir" ]]; then
        log_info "Zeek source exists"
        { [[ "$NON_INTERACTIVE" == true ]] || ! prompt_yes_no "Re-download? [y/N]" "n"; } && { log_success "Using existing source"; return 0; }
        rm -rf "$zeek_dir"
    fi
    
    log_info "Downloading..."
    curl -fSL --progress-bar -o "zeek-$ZEEK_VERSION.tar.gz" "https://download.zeek.org/zeek-$ZEEK_VERSION.tar.gz" || { log_error "Download failed"; exit 1; }
    tar -xzf "zeek-$ZEEK_VERSION.tar.gz"; rm -f "zeek-$ZEEK_VERSION.tar.gz"
    log_success "Source ready at $zeek_dir"
}

compile_zeek() {
    log_header "Compiling Zeek (15-45 minutes)"
    
    local src_dir="/usr/local/src/zeek-$ZEEK_VERSION" build_dir="/usr/local/src/zeek-$ZEEK_VERSION/build"
    
    [[ -z "$COMPILE_JOBS" ]] && { COMPILE_JOBS=$(nproc 2>/dev/null || echo "2"); [[ "$COMPILE_JOBS" -gt 2 ]] && COMPILE_JOBS=$((COMPILE_JOBS - 1)); }
    log_info "Using $COMPILE_JOBS parallel jobs"
    
    cd "$src_dir"; [[ -d "$build_dir" ]] && rm -rf "$build_dir"; mkdir -p "$build_dir"; cd "$build_dir"
    
    log_info "Configuring..."
    cmake .. -DCMAKE_INSTALL_PREFIX="$ZEEK_PREFIX" -DCMAKE_BUILD_TYPE=Release -DENABLE_PERFTOOLS=OFF -DINSTALL_ZEEKCTL=ON -DINSTALL_ZKG=ON 2>&1 | tee /tmp/zeek-cmake.log || { log_error "CMake failed"; exit 1; }
    [[ ! -f Makefile ]] && { log_error "CMake did not generate Makefile"; exit 1; }
    log_success "Configuration complete"
    
    log_info "Compiling..."
    make -j"$COMPILE_JOBS" 2>&1 | tee /tmp/zeek-build.log || { log_error "Compilation failed"; tail -30 /tmp/zeek-build.log; exit 1; }
    log_success "Compilation complete"
    
    log_info "Installing..."
    make install 2>&1 | tee /tmp/zeek-install.log || { log_error "Installation failed"; exit 1; }
    log_success "Zeek installed to $ZEEK_PREFIX"
}

configure_zeek() {
    log_header "Configuring Zeek"
    
    [[ ! -d "$ZEEK_PREFIX/etc" ]] && { log_error "Zeek etc directory not found"; exit 1; }
    
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

cleanup_repos() {
    log_header "Cleanup"
    if [[ "$NON_INTERACTIVE" != true ]] && prompt_yes_no "Remove Debian repos? [Y/n]" "y"; then
        rm -f /etc/apt/sources.list.d/debian-zeek-build.list
        apt-get update -qq 2>/dev/null || true
        log_success "Removed build repositories"
    else
        log_info "Keeping Debian repositories"
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
    echo "  • VyOS: $VYOS_VERSION | Zeek: $ZEEK_VERSION"
    echo "  • Path: $ZEEK_PREFIX"
    echo "  • Interfaces: ${MONITOR_INTERFACES[*]}"
    [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]] && echo "  • Mode: Standalone" || echo "  • Mode: Cluster (${#MONITOR_INTERFACES[@]} workers)"
    echo ""
    echo -e "${GREEN}Commands:${NC}"
    echo "  zeekctl status | deploy | stop"
    echo "  systemctl status zeek"
    echo ""
    echo -e "${YELLOW}Next: ./install-zeek-detection-suite.sh${NC}"
    echo ""
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface) IFS=',' read -ra MONITOR_INTERFACES <<< "$2"; for i in "${!MONITOR_INTERFACES[@]}"; do MONITOR_INTERFACES[$i]=$(echo "${MONITOR_INTERFACES[$i]}" | xargs); done; shift 2 ;;
            -n|--networks) LOCAL_NETWORKS="$2"; shift 2 ;;
            -v|--zeek-version) ZEEK_VERSION="$2"; shift 2 ;;
            -j|--jobs) COMPILE_JOBS="$2"; shift 2 ;;
            -y|--yes) NON_INTERACTIVE=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done
    
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        VYOS ZEEK INSTALLATION SCRIPT v1.1.0                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
    
    check_root
    log_step "1/9" "Detecting VyOS"; detect_vyos
    log_step "2/9" "Detecting Interfaces"; detect_interfaces; detect_networks
    log_step "3/9" "Configuring Repos"; setup_debian_repos
    log_step "4/9" "Installing Dependencies"; install_build_deps
    log_step "5/9" "Downloading Zeek"; download_zeek
    log_step "6/9" "Compiling Zeek"; compile_zeek
    log_step "7/9" "Configuring Zeek"; configure_zeek
    log_step "8/9" "Setting Up Services"; setup_zeekctl; create_systemd_service
    log_step "9/9" "Cleanup & Verify"; cleanup_repos; verify_installation || true
    print_summary
}

main "$@"
