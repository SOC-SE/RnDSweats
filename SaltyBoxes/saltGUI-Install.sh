#!/bin/bash
#
# Salt-GUI Installation Script
#
# Installs Salt-GUI and all dependencies on Debian or RHEL-based systems.
# Supports: Ubuntu, Debian, Rocky Linux, Oracle Linux, CentOS, Fedora, AlmaLinux
#
# Usage:
#   sudo ./install.sh              # Interactive installation
#   sudo ./install.sh --unattended # Non-interactive with defaults
#   sudo ./install.sh --help       # Show help
#
# Requirements:
#   - Root privileges (sudo)
#   - Internet connection
#   - Systemd-based system
#

set -euo pipefail

# ============================================================
# Configuration
# ============================================================

SCRIPT_VERSION="1.0.0"
INSTALL_DIR="/opt/salt-gui"
SERVICE_NAME="salt-gui"
SERVICE_USER="root"
NODE_MAJOR_VERSION="20"
MIN_NODE_VERSION="18"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Flags
UNATTENDED=false
SKIP_SALT=false
SKIP_NODE=false
FORCE_REINSTALL=false
INSTALL_SALT_MINION=true
SKIP_MINION=false

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}${BOLD}==>${NC} ${BOLD}$1${NC}"
}

log_substep() {
    echo -e "  ${CYAN}-->${NC} $1"
}

# Progress tracking
TOTAL_STEPS=13
CURRENT_STEP=0

log_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo -e "\n${BLUE}${BOLD}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${BOLD}$1${NC}"
}

# Spinner for long-running commands
# Usage: run_with_spinner "message" command arg1 arg2 ...
run_with_spinner() {
    local msg="$1"
    shift
    local spin_chars='|/-\'
    local pid
    local i=0
    local elapsed=0

    "$@" &>/tmp/salt-gui-install-cmd.log &
    pid=$!

    printf "  ${CYAN}-->${NC} %s... " "$msg"
    while kill -0 "$pid" 2>/dev/null; do
        local c=${spin_chars:i++%4:1}
        printf "\r  ${CYAN}-->${NC} %s... %s [%ds]" "$msg" "$c" "$elapsed"
        sleep 1
        elapsed=$((elapsed + 1))
    done

    wait "$pid"
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        printf "\r  ${CYAN}-->${NC} %s... ${GREEN}done${NC} [%ds]      \n" "$msg" "$elapsed"
    else
        printf "\r  ${CYAN}-->${NC} %s... ${RED}failed${NC} [%ds]      \n" "$msg" "$elapsed"
        echo -e "  ${RED}    Output:${NC}"
        tail -5 /tmp/salt-gui-install-cmd.log 2>/dev/null | sed 's/^/      /'
    fi
    return $exit_code
}

show_banner() {
    echo -e "${BOLD}"
    echo "============================================================"
    echo "  Salt-GUI Installation Script v${SCRIPT_VERSION}"
    echo "============================================================"
    echo -e "${NC}"
}

show_help() {
    cat << EOF
Salt-GUI Installation Script

Usage: sudo ./install.sh [OPTIONS]

Options:
    --help, -h          Show this help message
    --unattended        Run in non-interactive mode with defaults
    --skip-salt         Skip Salt Master/API installation
    --skip-node         Skip Node.js installation (use existing)
    --skip-minion       Skip Salt Minion installation (installed by default)
    --force             Force reinstallation even if already installed
    --install-dir DIR   Set installation directory (default: /opt/salt-gui)

Examples:
    sudo ./install.sh                    # Interactive installation (includes Salt Minion)
    sudo ./install.sh --unattended       # Automated installation
    sudo ./install.sh --skip-salt        # Only install Salt-GUI (Salt already installed)
    sudo ./install.sh --skip-minion      # Don't install Salt Minion on this host

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_systemd() {
    if ! command -v systemctl &>/dev/null; then
        log_error "This script requires systemd. Your system does not appear to use systemd."
        exit 1
    fi
}

check_internet() {
    log_substep "Checking internet connectivity..."
    if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null && ! ping -c 1 -W 5 1.1.1.1 &>/dev/null; then
        log_warn "No internet connectivity detected. Installation may fail."
        if [[ "$UNATTENDED" == "false" ]]; then
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
}

# ============================================================
# OS Detection
# ============================================================

detect_os() {
    log_progress "Detecting Operating System"

    OS_ID=""
    OS_VERSION=""
    OS_FAMILY=""
    PKG_MANAGER=""

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-$OS_ID}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
        OS_NAME=$(cat /etc/redhat-release)
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    # Determine OS family and package manager
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali)
            OS_FAMILY="debian"
            PKG_MANAGER="apt-get"
            ;;
        rhel|centos|rocky|almalinux|ol|oracle|fedora|scientific|amzn)
            OS_FAMILY="redhat"
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            ;;
        opensuse*|sles)
            OS_FAMILY="suse"
            PKG_MANAGER="zypper"
            log_error "SUSE-based systems are not yet supported."
            exit 1
            ;;
        arch|manjaro)
            OS_FAMILY="arch"
            PKG_MANAGER="pacman"
            log_error "Arch-based systems are not yet supported."
            exit 1
            ;;
        *)
            log_error "Unsupported OS: $OS_ID"
            log_error "This script supports Debian-based and RHEL-based distributions."
            exit 1
            ;;
    esac

    log_info "Detected: $OS_NAME"
    log_info "OS Family: $OS_FAMILY"
    log_info "Package Manager: $PKG_MANAGER"
}

# ============================================================
# Package Installation Functions
# ============================================================

update_package_cache() {
    case "$OS_FAMILY" in
        debian)
            run_with_spinner "Updating package cache" apt-get update -qq
            ;;
        redhat)
            run_with_spinner "Updating package cache" $PKG_MANAGER makecache -q || true
            ;;
    esac
}

install_base_packages() {
    log_progress "Installing Base Packages"

    local packages="curl wget git ca-certificates gnupg"

    case "$OS_FAMILY" in
        debian)
            run_with_spinner "Installing base packages" apt-get install -y -qq $packages software-properties-common apt-transport-https lsb-release
            ;;
        redhat)
            run_with_spinner "Installing base packages" $PKG_MANAGER install -y -q $packages
            # Install EPEL for additional packages on RHEL-based systems
            if [[ "$OS_ID" != "fedora" ]]; then
                if ! rpm -q epel-release &>/dev/null; then
                    log_substep "Installing EPEL repository..."
                    $PKG_MANAGER install -y -q epel-release || true
                fi
            fi
            ;;
    esac
}

# ============================================================
# Node.js Installation
# ============================================================

check_node_version() {
    if command -v node &>/dev/null; then
        local version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [[ "$version" -ge "$MIN_NODE_VERSION" ]]; then
            return 0
        fi
    fi
    return 1
}

install_nodejs() {
    log_progress "Installing Node.js"

    if [[ "$SKIP_NODE" == "true" ]]; then
        log_info "Skipping Node.js installation (--skip-node)"
        if ! check_node_version; then
            log_error "Node.js >= $MIN_NODE_VERSION is required but not found"
            exit 1
        fi
        return
    fi

    if check_node_version && [[ "$FORCE_REINSTALL" == "false" ]]; then
        log_info "Node.js $(node --version) already installed"
        return
    fi

    log_substep "Installing Node.js ${NODE_MAJOR_VERSION}.x..."

    case "$OS_FAMILY" in
        debian)
            # Remove old NodeSource config if present
            rm -f /etc/apt/sources.list.d/nodesource.list
            rm -f /etc/apt/keyrings/nodesource.gpg

            # Install using NodeSource
            mkdir -p /etc/apt/keyrings
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg

            echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR_VERSION}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list

            apt-get update -qq
            apt-get install -y -qq nodejs
            ;;
        redhat)
            # Remove old NodeSource config if present
            rm -f /etc/yum.repos.d/nodesource*.repo

            # Install using NodeSource
            curl -fsSL https://rpm.nodesource.com/setup_${NODE_MAJOR_VERSION}.x | bash -
            $PKG_MANAGER install -y -q nodejs
            ;;
    esac

    # Verify installation
    if ! check_node_version; then
        log_error "Node.js installation failed"
        exit 1
    fi

    log_info "Node.js $(node --version) installed successfully"
}

# ============================================================
# Salt Installation
# ============================================================

check_salt_installed() {
    if command -v salt-master &>/dev/null && command -v salt-api &>/dev/null; then
        return 0
    fi
    return 1
}

get_salt_repo_version() {
    # Salt uses different repo naming for different OS versions
    # Returns the Salt repo version string

    case "$OS_FAMILY" in
        debian)
            case "$OS_ID" in
                ubuntu)
                    echo "ubuntu/${OS_VERSION}"
                    ;;
                debian)
                    echo "debian/${OS_VERSION}"
                    ;;
                *)
                    # Default to debian
                    echo "debian/12"
                    ;;
            esac
            ;;
        redhat)
            local major_version=$(echo "$OS_VERSION" | cut -d'.' -f1)
            case "$OS_ID" in
                fedora)
                    echo "fedora/${major_version}"
                    ;;
                amzn)
                    echo "amazon/2"
                    ;;
                *)
                    # RHEL, Rocky, Oracle, CentOS, AlmaLinux
                    echo "redhat/${major_version}"
                    ;;
            esac
            ;;
    esac
}

install_salt() {
    log_progress "Installing Salt Master and API"

    if [[ "$SKIP_SALT" == "true" ]]; then
        log_info "Skipping Salt installation (--skip-salt)"
        if ! check_salt_installed; then
            log_warn "Salt Master/API not found. Salt-GUI requires Salt to function."
        fi
        return
    fi

    if check_salt_installed && [[ "$FORCE_REINSTALL" == "false" ]]; then
        log_info "Salt Master and API already installed"
        log_info "Salt version: $(salt-master --version 2>/dev/null | head -1)"
        return
    fi

    log_substep "Adding Salt repository..."

    case "$OS_FAMILY" in
        debian)
            # Import Salt GPG key
            mkdir -p /etc/apt/keyrings
            curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | gpg --dearmor -o /etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || {
                # Fallback to old key location
                curl -fsSL https://repo.saltproject.io/salt/py3/ubuntu/22.04/amd64/SALT-PROJECT-GPG-PUBKEY-2023.gpg | gpg --dearmor -o /etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || {
                    # Another fallback - try without GPG verification for older systems
                    log_warn "Could not fetch Salt GPG key, continuing without verification"
                }
            }

            # Add Salt repository - using latest stable
            # Try the new Broadcom repository first, fallback to old SaltProject repo
            local codename=$(lsb_release -cs 2>/dev/null || echo "jammy")

            cat > /etc/apt/sources.list.d/salt.list << EOF
deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.gpg] https://packages.broadcom.com/artifactory/saltproject-deb/ stable main
EOF

            apt-get update -qq 2>/dev/null || {
                # Fallback to old repository
                log_warn "New Salt repo failed, trying legacy repository..."
                echo "deb [arch=amd64] https://repo.saltproject.io/salt/py3/ubuntu/22.04/amd64/latest $codename main" > /etc/apt/sources.list.d/salt.list
                apt-get update -qq
            }

            log_substep "Installing Salt packages..."
            apt-get install -y -qq salt-master salt-api salt-common || {
                # If specific packages fail, try without salt-common
                apt-get install -y -qq salt-master salt-api
            }

            if [[ "$INSTALL_SALT_MINION" == "true" ]]; then
                apt-get install -y -qq salt-minion
            fi
            ;;

        redhat)
            # Import Salt GPG key
            rpm --import https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public 2>/dev/null || {
                rpm --import https://repo.saltproject.io/salt/py3/redhat/9/x86_64/SALT-PROJECT-GPG-PUBKEY-2023.pub 2>/dev/null || {
                    log_warn "Could not import Salt GPG key"
                }
            }

            local major_version=$(echo "$OS_VERSION" | cut -d'.' -f1)

            # Add Salt repository
            cat > /etc/yum.repos.d/salt.repo << EOF
[salt-repo]
name=Salt repo for RHEL/CentOS $major_version
baseurl=https://packages.broadcom.com/artifactory/saltproject-rpm/
enabled=1
gpgcheck=1
gpgkey=https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public
EOF

            log_substep "Installing Salt packages..."
            $PKG_MANAGER install -y -q salt-master salt-api || {
                # Fallback to old repository
                log_warn "New Salt repo failed, trying legacy repository..."
                cat > /etc/yum.repos.d/salt.repo << EOF
[salt-repo]
name=Salt repo for RHEL/CentOS $major_version
baseurl=https://repo.saltproject.io/salt/py3/redhat/${major_version}/\$basearch/latest
enabled=1
gpgcheck=0
EOF
                $PKG_MANAGER install -y -q salt-master salt-api
            }

            if [[ "$INSTALL_SALT_MINION" == "true" ]]; then
                $PKG_MANAGER install -y -q salt-minion
            fi
            ;;
    esac

    # Verify installation
    if ! check_salt_installed; then
        log_error "Salt installation failed"
        log_error "Please install Salt manually and run: ./install.sh --skip-salt"
        exit 1
    fi

    log_info "Salt installed successfully"
}

configure_salt_api() {
    log_progress "Configuring Salt API"

    local salt_api_conf="/etc/salt/master.d/api.conf"
    local salt_pki_dir="/etc/salt/pki/api"

    # Create config directory if needed
    mkdir -p /etc/salt/master.d

    # Always overwrite API config to ensure correct port
    if [[ -f "$salt_api_conf" ]]; then
        log_substep "Updating existing Salt API configuration..."
    fi

    log_substep "Generating SSL certificates..."
    mkdir -p "$salt_pki_dir"

    if [[ ! -f "$salt_pki_dir/salt-api.crt" ]] || [[ "$FORCE_REINSTALL" == "true" ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$salt_pki_dir/salt-api.key" \
            -out "$salt_pki_dir/salt-api.crt" \
            -subj "/CN=salt-api/O=Salt-GUI" 2>/dev/null

        chmod 600 "$salt_pki_dir/salt-api.key"
        chmod 644 "$salt_pki_dir/salt-api.crt"
    fi

    log_substep "Creating Salt API configuration..."
    cat > "$salt_api_conf" << 'EOF'
# Salt API Configuration for Salt-GUI
# Generated by Salt-GUI installer

rest_cherrypy:
  port: 8001
  ssl_crt: /etc/salt/pki/api/salt-api.crt
  ssl_key: /etc/salt/pki/api/salt-api.key
  # For testing without SSL, comment above and uncomment:
  # disable_ssl: True

# Required for Salt 3007+: explicitly enable API client types
netapi_enable_clients:
  - local
  - local_async
  - runner
  - wheel

# External authentication
# By default, use PAM authentication with root user
# Modify this for your security requirements
external_auth:
  pam:
    root:
      - .*
      - '@runner'
      - '@wheel'
    saltadmin:
      - .*
      - '@runner'
      - '@wheel'
EOF

    log_info "Salt API configured on port 8001 with SSL"

    # Salt Master must run as root for PAM authentication to work
    # (needs access to /etc/shadow)
    local master_user_conf="/etc/salt/master.d/user.conf"
    if [[ ! -f "$master_user_conf" ]]; then
        log_substep "Configuring Salt Master to run as root (required for PAM auth)..."
        cat > "$master_user_conf" << 'EOF'
# Run salt-master as root (required for PAM authentication)
user: root
EOF
    fi

    # Ensure SSL key is readable by salt-api
    chmod 644 "$salt_pki_dir/salt-api.key" 2>/dev/null || true
    chmod 644 "$salt_pki_dir/salt-api.crt" 2>/dev/null || true

    # Create saltadmin system user for PAM authentication
    if ! id -u saltadmin &>/dev/null; then
        log_substep "Creating saltadmin system user for Salt API authentication..."
        useradd -r -s /bin/bash saltadmin 2>/dev/null || true
        echo "saltadmin:saltadmin" | chpasswd
        log_info "Created saltadmin user (password: saltadmin)"
    fi

    # Configure Salt file_roots to include Salt-GUI states
    local file_roots_conf="/etc/salt/master.d/file_roots.conf"
    if [[ ! -f "$file_roots_conf" ]]; then
        log_substep "Configuring Salt file_roots to include Salt-GUI states..."
        cat > "$file_roots_conf" << EOF
# Include Salt-GUI states in Salt's file_roots
# States in ${INSTALL_DIR}/states/ are accessible via Salt state.apply
# e.g. linux.security.falco -> ${INSTALL_DIR}/states/linux/security/falco.sls
file_roots:
  base:
    - /srv/salt
    - ${INSTALL_DIR}/states
EOF
        mkdir -p /srv/salt
        log_info "Salt file_roots configured to include ${INSTALL_DIR}/states"
    fi

    # Install python-pam for PAM authentication support
    log_substep "Ensuring python-pam is available..."
    if [[ -x /opt/saltstack/salt/bin/pip3 ]]; then
        /opt/saltstack/salt/bin/pip3 install python-pam 2>/dev/null || true
    elif command -v pip3 &>/dev/null; then
        pip3 install python-pam 2>/dev/null || true
    fi
}

configure_salt_minion() {
    log_progress "Configuring Local Salt Minion"

    if [[ "$INSTALL_SALT_MINION" != "true" ]]; then
        return
    fi

    local minion_conf="/etc/salt/minion.d/local.conf"

    # Create minion config directory
    mkdir -p /etc/salt/minion.d

    # Configure minion to connect to localhost
    log_substep "Configuring minion to connect to local master..."
    cat > "$minion_conf" << EOF
# Local minion configuration for Salt-GUI
# This minion connects to the local Salt Master

master: localhost
id: $(hostname -s)

# Grains for identification
grains:
  roles:
    - salt-gui-server
  managed_by: salt-gui
EOF

    log_info "Minion configured to connect to localhost"

    # Setup auditd for forensic monitoring
    log_substep "Installing auditd for forensic watch rules..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq auditd 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y -q audit 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y -q audit 2>/dev/null || true
    fi
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/saltgui-forensics.rules << 'AUDITRULES'
-w /etc/passwd -p wa -k user_mod
-w /etc/shadow -p wa -k user_mod
-w /etc/sudoers -p wa -k sudo_mod
-w /etc/ssh/sshd_config -p wa -k ssh_mod
-w /etc/crontab -p wa -k cron_mod
-w /etc/cron.d/ -p wa -k cron_mod
-w /etc/pam.d/ -p wa -k pam_mod
-w /etc/ld.so.preload -p wa -k preload_mod
-w /etc/profile.d/ -p wa -k profile_mod
-w /etc/systemd/system/ -p wa -k systemd_mod
-a always,exit -F dir=/tmp -F perm=x -k tmp_exec
-a always,exit -F dir=/dev/shm -F perm=x -k shm_exec
AUDITRULES
    systemctl enable auditd 2>/dev/null || true
    augenrules --load 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    log_info "Auditd configured with 12 forensic watch rules"
}

start_salt_services() {
    log_progress "Starting Salt Services"

    # Enable and restart salt-master (restart to pick up any config changes)
    log_substep "Starting salt-master..."
    systemctl enable salt-master 2>/dev/null || true
    systemctl restart salt-master 2>/dev/null || systemctl start salt-master

    # Wait for salt-master to be ready
    sleep 3

    # Enable and restart salt-api (restart to pick up any config changes)
    log_substep "Starting salt-api..."
    systemctl enable salt-api 2>/dev/null || true
    systemctl restart salt-api 2>/dev/null || systemctl start salt-api

    # Start minion if installed
    if [[ "$INSTALL_SALT_MINION" == "true" ]] && command -v salt-minion &>/dev/null; then
        log_substep "Starting salt-minion..."
        systemctl enable salt-minion --now 2>/dev/null || {
            systemctl enable salt-minion
            systemctl start salt-minion
        }

        # Wait for minion to connect and then auto-accept its key
        log_substep "Waiting for minion to connect..."
        sleep 5

        # Auto-accept the local minion's key
        local hostname=$(hostname -s)
        log_substep "Auto-accepting local minion key ($hostname)..."
        salt-key -y -a "$hostname" 2>/dev/null || {
            # If exact hostname doesn't work, accept all pending
            sleep 2
            salt-key -y -A 2>/dev/null || log_warn "Could not auto-accept minion key"
        }
    fi

    # Verify services are running
    sleep 2

    if systemctl is-active --quiet salt-master; then
        log_info "salt-master is running"
    else
        log_warn "salt-master may not be running properly"
    fi

    if systemctl is-active --quiet salt-api; then
        log_info "salt-api is running"
    else
        log_warn "salt-api may not be running properly"
    fi

    if [[ "$INSTALL_SALT_MINION" == "true" ]]; then
        if systemctl is-active --quiet salt-minion; then
            log_info "salt-minion is running"
        else
            log_warn "salt-minion may not be running properly"
        fi
    fi
}

# ============================================================
# Salt-GUI Installation
# ============================================================

install_salt_gui() {
    log_progress "Installing Salt-GUI"

    local source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Create installation directory
    if [[ -d "$INSTALL_DIR" ]] && [[ "$FORCE_REINSTALL" == "false" ]]; then
        log_warn "Installation directory already exists: $INSTALL_DIR"
        if [[ "$UNATTENDED" == "false" ]]; then
            read -p "Overwrite existing installation? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Keeping existing installation"
                return
            fi
        fi
    fi

    log_substep "Creating installation directory..."
    mkdir -p "$INSTALL_DIR"

    # Copy files
    log_substep "Copying application files..."

    # If running from source directory, copy files
    if [[ -f "$source_dir/server.js" ]]; then
        cp -r "$source_dir"/{server.js,package.json,package-lock.json,src,public,config,scripts,states,playbooks,logs} "$INSTALL_DIR/" 2>/dev/null || {
            # If some directories don't exist, copy what we can
            cp "$source_dir/server.js" "$INSTALL_DIR/"
            cp "$source_dir/package.json" "$INSTALL_DIR/"
            [[ -f "$source_dir/package-lock.json" ]] && cp "$source_dir/package-lock.json" "$INSTALL_DIR/"
            cp -r "$source_dir/src" "$INSTALL_DIR/"
            cp -r "$source_dir/public" "$INSTALL_DIR/"
            mkdir -p "$INSTALL_DIR"/{config,scripts/linux,scripts/windows,states/linux,states/windows,playbooks,logs}
            [[ -d "$source_dir/config" ]] && cp -r "$source_dir/config"/* "$INSTALL_DIR/config/" 2>/dev/null || true
        }
    else
        log_error "Source files not found. Run this script from the Salt-GUI directory."
        exit 1
    fi

    # Ensure directories exist
    mkdir -p "$INSTALL_DIR"/{scripts/linux,scripts/windows,states/linux,states/windows,playbooks,logs}

    # Install npm dependencies
    log_substep "Installing npm dependencies..."
    cd "$INSTALL_DIR"
    npm install --omit=dev --loglevel=info 2>&1 | while IFS= read -r line; do
        # Show package-level progress
        if [[ "$line" == *"added"* ]] || [[ "$line" == *"npm warn"* ]] || [[ "$line" == *"packages in"* ]]; then
            echo "      $line"
        fi
    done
    local npm_exit=${PIPESTATUS[0]}
    if [[ $npm_exit -eq 0 ]]; then
        log_info "npm dependencies installed"
    else
        log_error "npm install failed (exit code $npm_exit)"
        log_error "Trying again with verbose output..."
        npm install --omit=dev
    fi

    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 640 "$INSTALL_DIR/config"/*.yaml 2>/dev/null || true

    log_info "Salt-GUI installed to $INSTALL_DIR"
}

configure_salt_gui() {
    log_progress "Configuring Salt-GUI"

    local config_dir="$INSTALL_DIR/config"

    # Create config directory
    mkdir -p "$config_dir"

    # Create app.yaml if it doesn't exist
    if [[ ! -f "$config_dir/app.yaml" ]]; then
        log_substep "Creating app.yaml..."
        cat > "$config_dir/app.yaml" << EOF
# Salt-GUI Application Configuration

server:
  port: 3000
  host: "0.0.0.0"

session:
  timeout_minutes: 30
  # secret: "generate-a-secure-secret-here"  # Auto-generated if not set

logging:
  level: "info"
  audit_file: "logs/audit.yaml"
EOF
    fi

    # Create salt.yaml if it doesn't exist
    if [[ ! -f "$config_dir/salt.yaml" ]]; then
        log_substep "Creating salt.yaml (API URL: https://127.0.0.1:8001)..."
        cat > "$config_dir/salt.yaml" << EOF
# Salt API Connection Configuration

api:
  url: "https://127.0.0.1:8001"
  username: "saltadmin"
  password: "saltadmin"
  eauth: "pam"
  verify_ssl: false  # Set to true in production with valid certs

defaults:
  timeout: 30
  batch_size: 10
EOF

        log_info "Salt API configured with saltadmin user"
    fi

    # Create auth.yaml if it doesn't exist
    if [[ ! -f "$config_dir/auth.yaml" ]]; then
        log_substep "Creating auth.yaml with default admin user..."
        cat > "$config_dir/auth.yaml" << 'EOF'
# Salt-GUI User Authentication
# Passwords are stored as bcrypt hashes
# Default: admin / Changeme1!

users:
  admin:
    password_hash: "$2b$12$fzH7uhWZxv9ssFBWmmUyn.aysvz7NJV4xFT1cWUW26BOQabWzKKhO"
    role: admin
EOF
    fi

    # Set secure permissions on config files
    chmod 640 "$config_dir"/*.yaml
    chown -R "$SERVICE_USER:$SERVICE_USER" "$config_dir"

    log_info "Configuration files created in $config_dir"
}

create_systemd_service() {
    log_progress "Creating Systemd Service"

    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    log_substep "Creating service file..."
    cat > "$service_file" << EOF
[Unit]
Description=Salt-GUI Web Interface
Documentation=https://github.com/your-repo/salt-gui
After=network.target salt-master.service salt-api.service
Wants=salt-api.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=salt-gui
Environment=NODE_ENV=production

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/logs $INSTALL_DIR/config /var/cache/salt/master/minions
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # Ensure ReadWritePaths directories exist before service start
    mkdir -p /var/cache/salt/master/minions

    # Reload systemd
    systemctl daemon-reload

    log_info "Systemd service created: $SERVICE_NAME"
}

start_salt_gui() {
    log_progress "Starting Salt-GUI"

    log_substep "Enabling and starting service..."
    systemctl enable "$SERVICE_NAME" --now 2>/dev/null || {
        systemctl enable "$SERVICE_NAME"
        systemctl start "$SERVICE_NAME"
    }

    # Wait for startup
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Salt-GUI is running"
    else
        log_error "Salt-GUI failed to start"
        log_error "Check logs with: journalctl -u $SERVICE_NAME -f"
        return 1
    fi
}

# ============================================================
# Post-Installation
# ============================================================

configure_firewall() {
    log_progress "Configuring Firewall"

    for port in 3000 4505 4506 8001; do
        iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    done
    log_info "iptables rules added for ports 3000, 4505, 4506, 8001"
}

show_completion_message() {
    local ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

    echo ""
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}  Installation Complete!${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo ""
    echo -e "  ${BOLD}Salt-GUI URL:${NC}     http://${ip_addr}:3000"
    echo -e "  ${BOLD}Install Dir:${NC}      $INSTALL_DIR"
    echo ""
    echo -e "  ${BOLD}Services:${NC}"
    echo -e "    salt-master:  $(systemctl is-active salt-master 2>/dev/null || echo 'unknown')"
    echo -e "    salt-api:     $(systemctl is-active salt-api 2>/dev/null || echo 'unknown')"
    echo -e "    salt-minion:  $(systemctl is-active salt-minion 2>/dev/null || echo 'not installed')"
    echo -e "    salt-gui:     $(systemctl is-active $SERVICE_NAME 2>/dev/null || echo 'unknown')"
    echo ""
    echo -e "  ${BOLD}Next Steps:${NC}"
    echo -e "    1. Open http://${ip_addr}:3000 in your browser"
    echo -e "    2. Create an admin user on first access"
    echo -e "    3. Configure Salt API credentials in Settings"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    Salt API:     /etc/salt/master.d/api.conf"
    echo -e "    Salt-GUI:     $INSTALL_DIR/config/"
    echo ""
    echo -e "  ${BOLD}Useful Commands:${NC}"
    echo -e "    View logs:    journalctl -u $SERVICE_NAME -f"
    echo -e "    Restart:      systemctl restart $SERVICE_NAME"
    echo -e "    Status:       systemctl status $SERVICE_NAME"
    echo ""

    if [[ ! -f "$INSTALL_DIR/config/salt.yaml" ]] || grep -q 'password: ""' "$INSTALL_DIR/config/salt.yaml" 2>/dev/null; then
        echo -e "  ${YELLOW}${BOLD}[ACTION REQUIRED]${NC}"
        echo -e "    Configure Salt API password in:"
        echo -e "    $INSTALL_DIR/config/salt.yaml"
        echo ""
    fi

    echo -e "${GREEN}============================================================${NC}"
    echo ""
}

# ============================================================
# Uninstall Function
# ============================================================

uninstall() {
    log_step "Uninstalling Salt-GUI"

    # Stop and disable salt-gui service
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_substep "Stopping $SERVICE_NAME service..."
        systemctl stop "$SERVICE_NAME"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_substep "Disabling $SERVICE_NAME service..."
        systemctl disable "$SERVICE_NAME"
    fi

    # Remove service file
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        log_substep "Removing systemd service file..."
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi

    # Remove installation directory
    if [[ -d "$INSTALL_DIR" ]]; then
        log_substep "Removing installation directory ($INSTALL_DIR)..."
        rm -rf "$INSTALL_DIR"
    fi

    # Remove Salt API configuration files created by installer
    local removed_salt_conf=false
    for conf in /etc/salt/master.d/api.conf /etc/salt/master.d/user.conf /etc/salt/master.d/file_roots.conf; do
        if [[ -f "$conf" ]] && grep -q "Salt-GUI" "$conf" 2>/dev/null; then
            log_substep "Removing $conf..."
            rm -f "$conf"
            removed_salt_conf=true
        fi
    done

    # Remove SSL certificates generated by installer
    if [[ -d "/etc/salt/pki/api" ]]; then
        log_substep "Removing Salt API SSL certificates..."
        rm -rf "/etc/salt/pki/api"
    fi

    # Remove saltadmin system user created by installer
    if id -u saltadmin &>/dev/null; then
        log_substep "Removing saltadmin system user..."
        userdel saltadmin 2>/dev/null || true
    fi

    # Remove auditd rules created by installer
    if [[ -f "/etc/audit/rules.d/saltgui-forensics.rules" ]]; then
        log_substep "Removing auditd forensic rules..."
        rm -f "/etc/audit/rules.d/saltgui-forensics.rules"
        augenrules --load 2>/dev/null || true
        systemctl restart auditd 2>/dev/null || true
    fi

    # Remove firewall rules added by installer
    for port in 3000 4505 4506 8001; do
        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    done

    # Restart salt-api/salt-master if we removed their config
    if [[ "$removed_salt_conf" == "true" ]]; then
        log_substep "Restarting Salt services after config removal..."
        systemctl restart salt-master 2>/dev/null || true
        systemctl restart salt-api 2>/dev/null || true
    fi

    log_info "Salt-GUI has been fully uninstalled"
    log_info "Salt Master, API, and Minion packages were NOT removed"
}

# ============================================================
# Main
# ============================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --unattended)
                UNATTENDED=true
                shift
                ;;
            --skip-salt)
                SKIP_SALT=true
                shift
                ;;
            --skip-node)
                SKIP_NODE=true
                shift
                ;;
            --force)
                FORCE_REINSTALL=true
                shift
                ;;
            --skip-minion)
                INSTALL_SALT_MINION=false
                shift
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --uninstall)
                check_root
                uninstall
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    show_banner

    # Pre-flight checks
    check_root
    check_systemd
    detect_os
    check_internet

    # Check for previous installation and offer full removal
    if [[ -d "$INSTALL_DIR" ]] || systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_warn "A previous Salt-GUI installation was detected."
        local do_uninstall=false
        if [[ "$UNATTENDED" == "false" ]]; then
            read -p "Remove previous installation before continuing? [y/N] " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ ]] && do_uninstall=true
        elif [[ "$FORCE_REINSTALL" == "true" ]]; then
            do_uninstall=true
        fi

        if [[ "$do_uninstall" == "true" ]]; then
            uninstall
        fi
    fi

    # Installation steps
    update_package_cache
    install_base_packages
    install_nodejs
    install_salt
    configure_salt_api
    configure_salt_minion
    start_salt_services
    install_salt_gui
    configure_salt_gui
    create_systemd_service
    start_salt_gui
    configure_firewall

    # Done
    show_completion_message
}

# Run main
main "$@"
