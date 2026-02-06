#!/bin/bash
#===============================================================================
#
#  ███████╗███████╗███████╗██╗  ██╗    ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     
#  ╚══███╔╝██╔════╝██╔════╝██║ ██╔╝    ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     
#    ███╔╝ █████╗  █████╗  █████╔╝     ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     
#   ███╔╝  ██╔══╝  ██╔══╝  ██╔═██╗     ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     
#  ███████╗███████╗███████╗██║  ██╗    ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
#  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
#
#  Universal Zeek Installation Script
#  Version: 1.1.0
#
#  Installs Zeek Network Security Monitor on multiple Linux distributions:
#    • Ubuntu 20.04, 22.04, 24.04
#    • Debian 11 (Bullseye), 12 (Bookworm)
#    • RHEL 8, 9 / CentOS Stream 8, 9 / Rocky Linux 8, 9 / AlmaLinux 8, 9
#    • Fedora 38, 39, 40, 41
#    • Arch Linux
#
#  Installation Methods:
#    1. Binary packages (preferred - via OpenSUSE Build Service)
#    2. Compile from source (fallback or when requested)
#
#  Usage: ./install-zeek-linux.sh [options]
#
#  Options:
#    -i, --interface IFACE   Network interface(s) to monitor (comma-separated)
#    -n, --networks CIDR     Local networks (comma-separated, default: RFC1918)
#    -m, --method METHOD     Installation method: auto|package|source (default: auto)
#    -v, --zeek-version VER  Zeek version for source build (default: 7.0.4)
#    -j, --jobs N            Parallel compile jobs (default: nproc-1)
#    -y, --yes               Non-interactive mode
#    -h, --help              Show this help message
#
#===============================================================================

set -euo pipefail

#===============================================================================
# CONFIGURATION
#===============================================================================

# Save original arguments for sudo hint
ORIGINAL_ARGS=("$@")

# Colors
if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
fi

# Defaults
MONITOR_INTERFACES=()      # Array of interfaces to monitor
LOCAL_NETWORKS=""
INSTALL_METHOD="auto"
ZEEK_VERSION="7.0.4"
COMPILE_JOBS=""
NON_INTERACTIVE=false
ZEEK_PREFIX="/opt/zeek"

# Distribution detection
DISTRO_ID=""
DISTRO_VERSION=""
DISTRO_CODENAME=""
DISTRO_FAMILY=""  # debian, rhel, fedora, arch
PKG_MANAGER=""
HAS_PACKAGES=false

#===============================================================================
# HELPER FUNCTIONS
#===============================================================================

log_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${MAGENTA}[STEP $1]${NC} $2"
}

show_help() {
    cat << 'EOF'
Universal Zeek Installation Script

Installs Zeek Network Security Monitor on multiple Linux distributions.
Supports both binary packages (preferred) and source compilation.

Usage: ./install-zeek-linux.sh [options]

Options:
  -i, --interface IFACE   Network interface(s) to monitor, comma-separated
                          Examples: -i eth0  OR  -i "eth0,eth1,eth2"
  -n, --networks CIDR     Local networks, comma-separated (default: RFC1918)
  -m, --method METHOD     Installation method: auto|package|source
  -v, --zeek-version VER  Zeek version for source build (default: 7.0.4)
  -j, --jobs N            Parallel compile jobs (default: nproc-1)
  -y, --yes               Non-interactive mode
  -h, --help              Show this help message

Supported Distributions:
  Debian Family:
    • Ubuntu 20.04 (Focal), 22.04 (Jammy), 24.04 (Noble)
    • Debian 11 (Bullseye), 12 (Bookworm)

  RHEL Family:
    • RHEL 8, 9
    • CentOS Stream 8, 9
    • Rocky Linux 8, 9
    • AlmaLinux 8, 9

  Fedora:
    • Fedora 38, 39, 40, 41

  Arch:
    • Arch Linux (source compilation)

Installation Methods:
  auto    - Use packages if available, fall back to source
  package - Binary packages only (fails if unavailable)
  source  - Always compile from source

Interface Selection:
  Single interface:    -i eth0
  Multiple interfaces: -i "eth0,eth1"    (uses cluster mode)
  
  For routers/firewalls, monitor LAN-facing interface(s) to see:
    • Internal source IPs (not NAT'd)
    • Lateral movement between internal hosts
    • C2 beacons with actual infected host IPs

Examples:
  # Auto-detect everything
  ./install-zeek-linux.sh

  # Single interface
  ./install-zeek-linux.sh -i eth0

  # Multiple interfaces (cluster mode)
  ./install-zeek-linux.sh -i "eth0,eth1,eth2"

  # Force source compilation
  ./install-zeek-linux.sh -m source -v 7.0.4 -j 8

  # Non-interactive with all options
  ./install-zeek-linux.sh -i "eth0,eth1" -n "10.0.0.0/8" -m auto -y

Post-Installation:
  After this script completes, run the detection suite installer:
  ./install-zeek-detection-suite.sh

EOF
}

prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    
    if [[ "$NON_INTERACTIVE" == true ]]; then
        [[ "$default" == "y" ]] && return 0 || return 1
    fi
    
    local yn
    while true; do
        read -r -p "$prompt " yn
        yn=${yn:-$default}
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        if [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]]; then
            log_info "Try: sudo $0 ${ORIGINAL_ARGS[*]}"
        else
            log_info "Try: sudo $0"
        fi
        exit 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# Validate an interface exists
validate_interface() {
    local iface="$1"
    if ! ip link show "$iface" &>/dev/null; then
        return 1
    fi
    return 0
}

#===============================================================================
# DISTRIBUTION DETECTION
#===============================================================================

detect_distro() {
    log_header "Detecting Linux Distribution"
    
    # Read os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION="${VERSION_ID:-}"
        DISTRO_CODENAME="${VERSION_CODENAME:-}"
    else
        log_error "Cannot detect distribution - /etc/os-release not found"
        exit 1
    fi
    
    # Normalize distro ID
    DISTRO_ID=$(echo "$DISTRO_ID" | tr '[:upper:]' '[:lower:]')
    
    # Determine distribution family and package manager
    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop)
            DISTRO_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        rhel|centos|rocky|almalinux|ol|scientific)
            DISTRO_FAMILY="rhel"
            if command_exists dnf; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            ;;
        fedora)
            DISTRO_FAMILY="fedora"
            PKG_MANAGER="dnf"
            ;;
        arch|manjaro|endeavouros)
            DISTRO_FAMILY="arch"
            PKG_MANAGER="pacman"
            ;;
        *)
            log_warning "Unknown distribution: $DISTRO_ID"
            log_info "Will attempt source compilation"
            DISTRO_FAMILY="unknown"
            # Try to detect package manager
            if command_exists apt-get; then
                PKG_MANAGER="apt"
            elif command_exists dnf; then
                PKG_MANAGER="dnf"
            elif command_exists yum; then
                PKG_MANAGER="yum"
            elif command_exists pacman; then
                PKG_MANAGER="pacman"
            else
                PKG_MANAGER="unknown"
            fi
            ;;
    esac
    
    log_success "Distribution: $DISTRO_ID $DISTRO_VERSION${DISTRO_CODENAME:+ ($DISTRO_CODENAME)}"
    log_success "Family: $DISTRO_FAMILY"
    log_success "Package Manager: $PKG_MANAGER"
    
    # Check if this is a supported version
    check_distro_support
}

check_distro_support() {
    local supported=false
    HAS_PACKAGES=false
    
    case "$DISTRO_FAMILY" in
        debian)
            case "$DISTRO_ID" in
                ubuntu)
                    case "$DISTRO_VERSION" in
                        20.04|22.04|24.04) supported=true; HAS_PACKAGES=true ;;
                        *) supported=true ;;  # Try anyway
                    esac
                    ;;
                debian)
                    case "$DISTRO_VERSION" in
                        11|12) supported=true; HAS_PACKAGES=true ;;
                        *) supported=true ;;
                    esac
                    ;;
                *)
                    supported=true  # Debian derivatives
                    ;;
            esac
            ;;
        rhel)
            case "${DISTRO_VERSION%%.*}" in
                8|9) supported=true; HAS_PACKAGES=true ;;
                7) supported=true; log_warning "RHEL 7 is old - some features may be limited" ;;
                *) supported=true ;;
            esac
            ;;
        fedora)
            case "$DISTRO_VERSION" in
                38|39|40|41) supported=true; HAS_PACKAGES=true ;;
                *) supported=true ;;
            esac
            ;;
        arch)
            supported=true
            HAS_PACKAGES=false  # AUR requires manual intervention
            ;;
        *)
            supported=true  # Try source compilation
            ;;
    esac
    
    if [[ "$supported" != true ]]; then
        log_error "Unsupported distribution: $DISTRO_ID $DISTRO_VERSION"
        exit 1
    fi
    
    if [[ "$HAS_PACKAGES" != true ]] && [[ "$INSTALL_METHOD" == "package" ]]; then
        log_error "Binary packages not available for $DISTRO_ID $DISTRO_VERSION"
        log_info "Use --method source or --method auto"
        exit 1
    fi
}

#===============================================================================
# INTERFACE DETECTION
#===============================================================================

detect_interfaces() {
    log_header "Detecting Network Interfaces"
    
    # Get list of interfaces (excluding lo, docker, veth, br-, virbr, etc.)
    local all_interfaces
    all_interfaces=$(ip -o link show | awk -F': ' '{print $2}' | \
        grep -vE '^(lo|docker[0-9]*|veth|br-|virbr|vnet|tap|tun|wg)' | \
        sed 's/@.*//' | \
        sort -u)
    
    log_info "Available network interfaces:"
    echo ""
    
    local first_up=""
    for iface in $all_interfaces; do
        local state
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        local mac
        mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "unknown")
        local ip_addr
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)
        ip_addr="${ip_addr:-no IP}"
        
        printf "  %-15s %-10s %-18s %s\n" "$iface" "$state" "$mac" "$ip_addr"
        
        # Remember first UP interface
        if [[ -z "$first_up" ]] && [[ "$state" == "up" ]]; then
            first_up="$iface"
        fi
    done
    echo ""
    
    # If user specified interfaces, validate them
    if [[ ${#MONITOR_INTERFACES[@]} -gt 0 ]]; then
        local valid_interfaces=()
        for iface in "${MONITOR_INTERFACES[@]}"; do
            if validate_interface "$iface"; then
                valid_interfaces+=("$iface")
                log_success "Validated interface: $iface"
            else
                log_error "Interface not found: $iface"
                exit 1
            fi
        done
        MONITOR_INTERFACES=("${valid_interfaces[@]}")
    elif [[ -n "$first_up" ]]; then
        # Auto-select first UP interface
        log_info "Auto-selected interface: $first_up (first UP interface)"
        
        if [[ "$NON_INTERACTIVE" != true ]]; then
            echo ""
            echo -e "${YELLOW}Tip: For routers/firewalls, monitor LAN-facing interfaces${NC}"
            echo -e "${YELLOW}     to see internal IPs and lateral movement.${NC}"
            echo ""
            
            if ! prompt_yes_no "Use $first_up? [Y/n]" "y"; then
                read -r -p "Enter interface(s) to monitor (comma-separated): " user_input
                IFS=',' read -ra MONITOR_INTERFACES <<< "$user_input"
                # Trim whitespace
                for i in "${!MONITOR_INTERFACES[@]}"; do
                    MONITOR_INTERFACES[$i]=$(echo "${MONITOR_INTERFACES[$i]}" | xargs)
                done
            else
                MONITOR_INTERFACES=("$first_up")
            fi
        else
            MONITOR_INTERFACES=("$first_up")
        fi
        
        # Validate selected interfaces
        for iface in "${MONITOR_INTERFACES[@]}"; do
            if ! validate_interface "$iface"; then
                log_error "Interface not found: $iface"
                exit 1
            fi
        done
    else
        # No UP interface found
        if [[ "$NON_INTERACTIVE" == true ]]; then
            log_error "No UP interface found and running non-interactive"
            log_info "Specify interface with -i option"
            exit 1
        fi
        read -r -p "Enter interface(s) to monitor (comma-separated): " user_input
        IFS=',' read -ra MONITOR_INTERFACES <<< "$user_input"
        for i in "${!MONITOR_INTERFACES[@]}"; do
            MONITOR_INTERFACES[$i]=$(echo "${MONITOR_INTERFACES[$i]}" | xargs)
        done
    fi
    
    # Final validation
    if [[ ${#MONITOR_INTERFACES[@]} -eq 0 ]]; then
        log_error "No interfaces selected"
        exit 1
    fi
    
    # Report configuration mode
    if [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]]; then
        log_success "Configuration: Standalone mode (1 interface)"
    else
        log_success "Configuration: Cluster mode (${#MONITOR_INTERFACES[@]} interfaces)"
    fi
    
    log_success "Monitor interfaces: ${MONITOR_INTERFACES[*]}"
}

detect_networks() {
    if [[ -n "$LOCAL_NETWORKS" ]]; then
        log_info "Using specified networks: $LOCAL_NETWORKS"
        return
    fi
    
    # Default to RFC1918
    LOCAL_NETWORKS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    
    log_success "Local networks: $LOCAL_NETWORKS (RFC1918 defaults)"
}

#===============================================================================
# PACKAGE INSTALLATION - DEBIAN FAMILY
#===============================================================================

install_packages_debian() {
    log_header "Installing Zeek via APT (Debian/Ubuntu)"
    
    local obs_distro=""
    local obs_version=""
    
    # Map to OBS repository names
    case "$DISTRO_ID" in
        ubuntu)
            obs_distro="xUbuntu"
            case "$DISTRO_VERSION" in
                24.04) obs_version="24.04" ;;
                22.04) obs_version="22.04" ;;
                20.04) obs_version="20.04" ;;
                *)
                    log_warning "Ubuntu $DISTRO_VERSION may not have packages"
                    obs_version="$DISTRO_VERSION"
                    ;;
            esac
            ;;
        debian)
            obs_distro="Debian"
            case "$DISTRO_VERSION" in
                12) obs_version="12" ;;
                11) obs_version="11" ;;
                *)
                    log_warning "Debian $DISTRO_VERSION may not have packages"
                    obs_version="$DISTRO_VERSION"
                    ;;
            esac
            ;;
        *)
            log_warning "Unknown Debian derivative, trying Ubuntu 22.04 packages"
            obs_distro="xUbuntu"
            obs_version="22.04"
            ;;
    esac
    
    local repo_url="https://download.opensuse.org/repositories/security:/zeek/${obs_distro}_${obs_version}/"
    local key_url="${repo_url}Release.key"
    
    log_info "Adding Zeek repository..."
    log_info "Repository: $repo_url"
    
    # Install prerequisites
    apt-get update -qq
    apt-get install -y -qq curl gnupg apt-transport-https ca-certificates
    
    # Add GPG key with error checking
    log_info "Adding GPG key..."
    local key_file="/tmp/zeek-release.key"
    if ! curl -fsSL "$key_url" -o "$key_file"; then
        log_warning "Failed to download GPG key"
        rm -f "$key_file"
        return 1
    fi
    
    gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg < "$key_file"
    rm -f "$key_file"
    
    # Add repository
    echo "deb $repo_url /" > /etc/apt/sources.list.d/zeek.list
    
    # Update and install
    log_info "Updating package lists..."
    if ! apt-get update -qq 2>&1 | grep -v "^W:"; then
        log_warning "Repository may not exist for this version"
        rm -f /etc/apt/sources.list.d/zeek.list /etc/apt/trusted.gpg.d/security_zeek.gpg
        return 1
    fi
    
    log_info "Installing Zeek..."
    if ! apt-get install -y zeek 2>&1; then
        log_warning "Package installation failed"
        rm -f /etc/apt/sources.list.d/zeek.list /etc/apt/trusted.gpg.d/security_zeek.gpg
        return 1
    fi
    
    log_success "Zeek installed via APT"
    return 0
}

install_build_deps_debian() {
    log_info "Installing build dependencies (Debian/Ubuntu)..."
    
    apt-get update -qq
    apt-get install -y \
        build-essential \
        cmake \
        make \
        gcc \
        g++ \
        flex \
        bison \
        libpcap-dev \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        swig \
        zlib1g-dev \
        libmaxminddb-dev \
        git \
        curl
    
    # Optional dependencies (don't fail if unavailable)
    apt-get install -y \
        libkrb5-dev \
        libgoogle-perftools-dev \
        2>/dev/null || true
    
    log_success "Build dependencies installed"
}

#===============================================================================
# PACKAGE INSTALLATION - RHEL FAMILY
#===============================================================================

install_packages_rhel() {
    log_header "Installing Zeek via DNF/YUM (RHEL/CentOS/Rocky/Alma)"
    
    local major_version="${DISTRO_VERSION%%.*}"
    local obs_distro=""
    
    # Map to OBS repository
    case "$major_version" in
        9) obs_distro="CentOS_9_Stream" ;;
        8) obs_distro="CentOS_8_Stream" ;;
        *)
            log_warning "RHEL $major_version may not have packages"
            return 1
            ;;
    esac
    
    local repo_url="https://download.opensuse.org/repositories/security:/zeek/${obs_distro}/"
    
    log_info "Adding Zeek repository..."
    log_info "Repository: $repo_url"
    
    # Create repo file
    cat > /etc/yum.repos.d/zeek.repo << EOF
[zeek]
name=Zeek Security Monitoring
baseurl=${repo_url}
enabled=1
gpgcheck=1
gpgkey=${repo_url}repodata/repomd.xml.key
EOF

    # Install EPEL if needed (for dependencies)
    if ! rpm -q epel-release &>/dev/null; then
        log_info "Installing EPEL repository..."
        $PKG_MANAGER install -y epel-release 2>/dev/null || true
    fi
    
    # Install Zeek
    log_info "Installing Zeek..."
    if ! $PKG_MANAGER install -y zeek 2>&1; then
        log_warning "Package installation failed"
        rm -f /etc/yum.repos.d/zeek.repo
        return 1
    fi
    
    log_success "Zeek installed via $PKG_MANAGER"
    return 0
}

install_packages_fedora() {
    log_header "Installing Zeek via DNF (Fedora)"
    
    local obs_distro="Fedora_${DISTRO_VERSION}"
    local repo_url="https://download.opensuse.org/repositories/security:/zeek/${obs_distro}/"
    
    log_info "Adding Zeek repository..."
    
    cat > /etc/yum.repos.d/zeek.repo << EOF
[zeek]
name=Zeek Security Monitoring
baseurl=${repo_url}
enabled=1
gpgcheck=1
gpgkey=${repo_url}repodata/repomd.xml.key
EOF

    log_info "Installing Zeek..."
    if ! dnf install -y zeek 2>&1; then
        log_warning "Package installation failed"
        rm -f /etc/yum.repos.d/zeek.repo
        return 1
    fi
    
    log_success "Zeek installed via DNF"
    return 0
}

install_build_deps_rhel() {
    log_info "Installing build dependencies (RHEL family)..."
    
    # Enable PowerTools/CRB for build dependencies
    local major_version="${DISTRO_VERSION%%.*}"
    if [[ "$major_version" == "8" ]]; then
        $PKG_MANAGER config-manager --set-enabled powertools 2>/dev/null || \
        $PKG_MANAGER config-manager --set-enabled PowerTools 2>/dev/null || true
    elif [[ "$major_version" == "9" ]]; then
        $PKG_MANAGER config-manager --set-enabled crb 2>/dev/null || true
    fi
    
    # Install EPEL
    $PKG_MANAGER install -y epel-release 2>/dev/null || true
    
    # Development tools
    $PKG_MANAGER groupinstall -y "Development Tools" 2>/dev/null || \
    $PKG_MANAGER install -y gcc gcc-c++ make
    
    # Zeek dependencies
    $PKG_MANAGER install -y \
        cmake \
        flex \
        bison \
        libpcap-devel \
        openssl-devel \
        python3 \
        python3-devel \
        python3-pip \
        swig \
        zlib-devel \
        git \
        curl
    
    # Optional
    $PKG_MANAGER install -y \
        libmaxminddb-devel \
        krb5-devel \
        gperftools-devel \
        2>/dev/null || true
    
    log_success "Build dependencies installed"
}

#===============================================================================
# PACKAGE INSTALLATION - ARCH LINUX
#===============================================================================

install_packages_arch() {
    log_header "Installing Zeek on Arch Linux"
    
    log_warning "Zeek is available in AUR but requires manual build"
    log_info "This script will compile from source instead"
    
    # Arch doesn't have official Zeek packages
    return 1
}

install_build_deps_arch() {
    log_info "Installing build dependencies (Arch)..."
    
    pacman -Sy --noconfirm \
        base-devel \
        cmake \
        flex \
        bison \
        libpcap \
        openssl \
        python \
        swig \
        zlib \
        git \
        curl
    
    # Optional
    pacman -S --noconfirm \
        libmaxminddb \
        krb5 \
        gperftools \
        2>/dev/null || true
    
    log_success "Build dependencies installed"
}

#===============================================================================
# SOURCE COMPILATION
#===============================================================================

download_zeek_source() {
    log_header "Downloading Zeek $ZEEK_VERSION Source"
    
    local src_dir="/usr/local/src"
    local zeek_dir="$src_dir/zeek-$ZEEK_VERSION"
    local tarball="zeek-$ZEEK_VERSION.tar.gz"
    local url="https://download.zeek.org/$tarball"
    
    mkdir -p "$src_dir"
    cd "$src_dir"
    
    # Check if already exists
    if [[ -d "$zeek_dir" ]]; then
        log_info "Zeek source already exists"
        if [[ "$NON_INTERACTIVE" == true ]] || ! prompt_yes_no "Re-download? [y/N]" "n"; then
            log_success "Using existing source"
            return 0
        fi
        rm -rf "$zeek_dir"
    fi
    
    # Download
    log_info "Downloading from $url..."
    if ! curl -fSL --progress-bar -o "$tarball" "$url"; then
        log_error "Failed to download Zeek"
        log_info "Check: https://download.zeek.org/ for available versions"
        exit 1
    fi
    
    # Extract
    log_info "Extracting..."
    tar -xzf "$tarball"
    rm -f "$tarball"
    
    log_success "Source ready at $zeek_dir"
}

compile_zeek() {
    log_header "Compiling Zeek (15-45 minutes)"
    
    local src_dir="/usr/local/src/zeek-$ZEEK_VERSION"
    local build_dir="$src_dir/build"
    
    # Determine parallel jobs
    if [[ -z "$COMPILE_JOBS" ]]; then
        COMPILE_JOBS=$(nproc 2>/dev/null || echo "2")
        if [[ "$COMPILE_JOBS" -gt 1 ]]; then
            COMPILE_JOBS=$((COMPILE_JOBS - 1))
        fi
    fi
    
    log_info "Using $COMPILE_JOBS parallel jobs"
    
    cd "$src_dir"
    
    # Clean previous build
    [[ -d "$build_dir" ]] && rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Configure
    log_info "Configuring..."
    if ! cmake .. \
        -DCMAKE_INSTALL_PREFIX="$ZEEK_PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DINSTALL_ZEEKCTL=ON \
        -DINSTALL_ZKG=ON \
        2>&1 | tee /tmp/zeek-cmake.log; then
        log_error "Configuration failed - check /tmp/zeek-cmake.log"
        exit 1
    fi
    
    # Check cmake actually succeeded
    if [[ ! -f Makefile ]]; then
        log_error "CMake did not generate Makefile - check /tmp/zeek-cmake.log"
        exit 1
    fi
    
    log_success "Configuration complete"
    
    # Compile
    log_info "Compiling (this takes a while)..."
    echo ""
    
    if ! make -j"$COMPILE_JOBS" 2>&1 | tee /tmp/zeek-build.log; then
        log_error "Compilation failed - check /tmp/zeek-build.log"
        tail -50 /tmp/zeek-build.log
        exit 1
    fi
    
    log_success "Compilation complete"
    
    # Install
    log_info "Installing to $ZEEK_PREFIX..."
    if ! make install 2>&1 | tee /tmp/zeek-install.log; then
        log_error "Installation failed - check /tmp/zeek-install.log"
        exit 1
    fi
    
    log_success "Zeek installed to $ZEEK_PREFIX"
}

#===============================================================================
# ZEEK CONFIGURATION
#===============================================================================

configure_zeek() {
    log_header "Configuring Zeek"
    
    # Find Zeek installation
    if [[ -d "/opt/zeek" ]]; then
        ZEEK_PREFIX="/opt/zeek"
    elif [[ -d "/usr/local/zeek" ]]; then
        ZEEK_PREFIX="/usr/local/zeek"
    elif command_exists zeek; then
        ZEEK_PREFIX=$(dirname "$(dirname "$(command -v zeek)")")
    fi
    
    log_info "Zeek installation: $ZEEK_PREFIX"
    
    # Verify etc directory exists
    if [[ ! -d "$ZEEK_PREFIX/etc" ]]; then
        log_error "Zeek etc directory not found: $ZEEK_PREFIX/etc"
        exit 1
    fi
    
    # Add to PATH
    if [[ ! -f /etc/profile.d/zeek.sh ]]; then
        cat > /etc/profile.d/zeek.sh << EOF
# Zeek Network Security Monitor
export PATH="\$PATH:$ZEEK_PREFIX/bin"
EOF
        log_success "Added Zeek to PATH"
    fi
    
    export PATH="$PATH:$ZEEK_PREFIX/bin"
    
    # Configure networks.cfg
    log_info "Configuring local networks..."
    
    cat > "$ZEEK_PREFIX/etc/networks.cfg" << EOF
# Local networks for Zeek
# Generated by install-zeek-linux.sh

# RFC1918 Private Address Space
10.0.0.0/8          Private IP space
172.16.0.0/12       Private IP space
192.168.0.0/16      Private IP space
EOF

    log_success "Configured networks.cfg"
    
    # Configure node.cfg based on number of interfaces
    log_info "Configuring Zeek node..."
    
    if [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]]; then
        # Standalone mode - single interface
        cat > "$ZEEK_PREFIX/etc/node.cfg" << EOF
# Zeek Node Configuration - Standalone Mode
# Generated by install-zeek-linux.sh
#
# Single interface configuration

[zeek]
type=standalone
host=localhost
interface=${MONITOR_INTERFACES[0]}
EOF
        log_success "Configured standalone mode for interface ${MONITOR_INTERFACES[0]}"
    else
        # Cluster mode - multiple interfaces
        local node_cfg="$ZEEK_PREFIX/etc/node.cfg"
        cat > "$node_cfg" << EOF
# Zeek Node Configuration - Cluster Mode
# Generated by install-zeek-linux.sh
#
# Multi-interface configuration with ${#MONITOR_INTERFACES[@]} workers

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
        
        # Add a worker for each interface
        local worker_num=1
        for iface in "${MONITOR_INTERFACES[@]}"; do
            cat >> "$node_cfg" << EOF
[worker-$worker_num]
type=worker
host=localhost
interface=$iface

EOF
            ((worker_num++))
        done
        
        log_success "Configured cluster mode with ${#MONITOR_INTERFACES[@]} workers"
        log_info "Interfaces: ${MONITOR_INTERFACES[*]}"
    fi
    
    # Disable mail in zeekctl (optional)
    if [[ -f "$ZEEK_PREFIX/etc/zeekctl.cfg" ]]; then
        sed -i 's/^MailTo = .*/MailTo = /' "$ZEEK_PREFIX/etc/zeekctl.cfg" 2>/dev/null || true
    fi

    # Add -C flag to ignore checksums (NIC offloading causes invalid checksums on loopback/NAT traffic)
    # Without this, client TLS fingerprints (JA3/JA4) may not be captured correctly
    if [[ -f "$ZEEK_PREFIX/etc/zeekctl.cfg" ]] && ! grep -q "^ZeekArgs" "$ZEEK_PREFIX/etc/zeekctl.cfg"; then
        echo "ZeekArgs = -C" >> "$ZEEK_PREFIX/etc/zeekctl.cfg"
        log_info "Added ZeekArgs = -C to ignore checksums"
    fi
}

setup_zeekctl() {
    log_header "Initializing Zeek Control"
    
    if [[ ! -d "$ZEEK_PREFIX" ]]; then
        log_error "Zeek prefix not found: $ZEEK_PREFIX"
        exit 1
    fi
    
    cd "$ZEEK_PREFIX"
    
    log_info "Running zeekctl deploy..."
    
    "$ZEEK_PREFIX/bin/zeekctl" install 2>&1 || true
    "$ZEEK_PREFIX/bin/zeekctl" deploy 2>&1 || true
    
    log_info "Zeek status:"
    "$ZEEK_PREFIX/bin/zeekctl" status 2>&1 || true
    
    log_success "Zeek control initialized"
}

create_systemd_service() {
    log_header "Creating Systemd Service"
    
    # Check if service already exists (from package)
    if [[ -f /etc/systemd/system/zeek.service ]] || \
       [[ -f /lib/systemd/system/zeek.service ]]; then
        log_info "Systemd service already exists"
        systemctl daemon-reload
        systemctl enable zeek 2>/dev/null || true
        return 0
    fi
    
    cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
Environment="PATH=$ZEEK_PREFIX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$ZEEK_PREFIX/bin/zeekctl deploy
ExecStop=$ZEEK_PREFIX/bin/zeekctl stop
ExecReload=$ZEEK_PREFIX/bin/zeekctl restart
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable zeek 2>/dev/null || true
    
    log_success "Created and enabled zeek.service"
}

#===============================================================================
# VERIFICATION
#===============================================================================

verify_installation() {
    log_header "Verifying Installation"
    
    local errors=0
    
    # Check zeek binary
    local zeek_bin="$ZEEK_PREFIX/bin/zeek"
    if [[ -x "$zeek_bin" ]]; then
        local version
        version=$("$zeek_bin" --version 2>/dev/null) || version="unknown"
        log_success "Zeek binary: $version"
    elif command_exists zeek; then
        local version
        version=$(zeek --version 2>/dev/null) || version="unknown"
        log_success "Zeek binary: $version"
    else
        log_error "Zeek binary not found"
        ((errors++)) || true
    fi
    
    # Check zeekctl
    if [[ -x "$ZEEK_PREFIX/bin/zeekctl" ]] || command_exists zeekctl; then
        log_success "zeekctl installed"
    else
        log_warning "zeekctl not found"
    fi
    
    # Check configuration
    if [[ -f "$ZEEK_PREFIX/etc/node.cfg" ]]; then
        log_success "node.cfg configured"
        
        # Show configuration mode
        if grep -q "type=standalone" "$ZEEK_PREFIX/etc/node.cfg"; then
            log_info "Mode: Standalone"
        else
            local worker_count
            worker_count=$(grep -c "type=worker" "$ZEEK_PREFIX/etc/node.cfg" || echo "0")
            log_info "Mode: Cluster ($worker_count workers)"
        fi
    else
        log_warning "node.cfg not found"
    fi
    
    # Check if running
    if "$ZEEK_PREFIX/bin/zeekctl" status 2>/dev/null | grep -q "running"; then
        log_success "Zeek is running"
    else
        log_warning "Zeek is not currently running"
        log_info "Start with: zeekctl deploy"
    fi
    
    return $errors
}

print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ZEEK INSTALLATION COMPLETE                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Installation Summary:${NC}"
    echo "  • Distribution: $DISTRO_ID $DISTRO_VERSION"
    echo "  • Install Path: $ZEEK_PREFIX"
    echo "  • Interfaces:   ${MONITOR_INTERFACES[*]}"
    if [[ ${#MONITOR_INTERFACES[@]} -eq 1 ]]; then
        echo "  • Mode:         Standalone"
    else
        echo "  • Mode:         Cluster (${#MONITOR_INTERFACES[@]} workers)"
    fi
    echo ""
    echo -e "${GREEN}Key Paths:${NC}"
    echo "  • Binary:     $ZEEK_PREFIX/bin/zeek"
    echo "  • Config:     $ZEEK_PREFIX/etc/"
    echo "  • Logs:       $ZEEK_PREFIX/logs/current/"
    echo "  • Scripts:    $ZEEK_PREFIX/share/zeek/site/"
    echo ""
    echo -e "${GREEN}Management Commands:${NC}"
    echo "  zeekctl status      - Check Zeek status"
    echo "  zeekctl deploy      - Start/restart Zeek"
    echo "  zeekctl stop        - Stop Zeek"
    echo "  systemctl status zeek"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo ""
    echo "  1. Verify Zeek is capturing traffic:"
    echo "     tail -f $ZEEK_PREFIX/logs/current/conn.log"
    echo ""
    echo "  2. Install the detection suite:"
    echo -e "     ${BOLD}./install-zeek-detection-suite.sh${NC}"
    echo ""
}

#===============================================================================
# MAIN INSTALLATION LOGIC
#===============================================================================

install_via_packages() {
    case "$DISTRO_FAMILY" in
        debian)
            install_packages_debian
            ;;
        rhel)
            install_packages_rhel
            ;;
        fedora)
            install_packages_fedora
            ;;
        arch)
            install_packages_arch
            ;;
        *)
            return 1
            ;;
    esac
}

install_via_source() {
    # Install build dependencies based on distro
    case "$DISTRO_FAMILY" in
        debian)
            install_build_deps_debian
            ;;
        rhel|fedora)
            install_build_deps_rhel
            ;;
        arch)
            install_build_deps_arch
            ;;
        *)
            log_warning "Unknown distro family - attempting Debian-style build deps"
            install_build_deps_debian 2>/dev/null || \
            install_build_deps_rhel 2>/dev/null || true
            ;;
    esac
    
    download_zeek_source
    compile_zeek
}

do_install() {
    case "$INSTALL_METHOD" in
        package)
            log_info "Installation method: packages only"
            if ! install_via_packages; then
                log_error "Package installation failed"
                exit 1
            fi
            ;;
        source)
            log_info "Installation method: compile from source"
            install_via_source
            ;;
        auto|*)
            log_info "Installation method: auto (try packages, fall back to source)"
            if [[ "$HAS_PACKAGES" == true ]]; then
                if install_via_packages; then
                    log_success "Installed via packages"
                else
                    log_warning "Package installation failed, trying source..."
                    install_via_source
                fi
            else
                log_info "No packages available, compiling from source..."
                install_via_source
            fi
            ;;
    esac
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                # Parse comma-separated interfaces
                IFS=',' read -ra MONITOR_INTERFACES <<< "$2"
                # Trim whitespace from each interface
                for i in "${!MONITOR_INTERFACES[@]}"; do
                    MONITOR_INTERFACES[$i]=$(echo "${MONITOR_INTERFACES[$i]}" | xargs)
                done
                shift 2
                ;;
            -n|--networks)
                LOCAL_NETWORKS="$2"
                shift 2
                ;;
            -m|--method)
                INSTALL_METHOD="$2"
                if [[ ! "$INSTALL_METHOD" =~ ^(auto|package|source)$ ]]; then
                    log_error "Invalid method: $INSTALL_METHOD (use: auto|package|source)"
                    exit 1
                fi
                shift 2
                ;;
            -v|--zeek-version)
                ZEEK_VERSION="$2"
                shift 2
                ;;
            -j|--jobs)
                COMPILE_JOBS="$2"
                shift 2
                ;;
            -y|--yes)
                NON_INTERACTIVE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Banner
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        UNIVERSAL ZEEK INSTALLATION SCRIPT                      ║${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}║  Supports: Ubuntu, Debian, RHEL, CentOS, Rocky, Alma,          ║${NC}"
    echo -e "${CYAN}║            Fedora, Arch, and more                              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Pre-flight
    check_root
    
    # Step 1: Detect distribution
    log_step "1/7" "Detecting Linux Distribution"
    detect_distro
    
    # Step 2: Detect interfaces
    log_step "2/7" "Detecting Network Interfaces"
    detect_interfaces
    detect_networks
    
    # Step 3: Install Zeek
    log_step "3/7" "Installing Zeek"
    do_install
    
    # Step 4: Configure
    log_step "4/7" "Configuring Zeek"
    configure_zeek
    
    # Step 5: Setup zeekctl
    log_step "5/7" "Setting Up Zeek Control"
    setup_zeekctl
    
    # Step 6: Create service
    log_step "6/7" "Creating Systemd Service"
    create_systemd_service
    
    # Step 7: Verify
    log_step "7/7" "Verifying Installation"
    verify_installation || true
    
    # Summary
    print_summary
}

# Run
main "$@"
