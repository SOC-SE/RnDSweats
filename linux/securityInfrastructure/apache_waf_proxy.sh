#!/bin/bash
#===============================================================================
# Apache WAF Reverse Proxy Setup Script
#===============================================================================
# Description: Deploys HAProxy as a reverse proxy with Coraza WAF (SPOA)
#              in front of Apache web servers
#
# Architecture:
#   Client (port 80) -> HAProxy -> Coraza SPOA (WAF) -> Apache (port 8080)
#
# WAF Engine: Coraza (https://coraza.io)
#   - Modern OWASP ModSecurity replacement
#   - Full OWASP Core Rule Set v4 compatibility
#   - Better accuracy and actively maintained
#   - Uses SPOE (Stream Processing Offload Engine) for HAProxy integration
#
# Features:
#   - HAProxy reverse proxy on port 80
#   - Coraza WAF with OWASP Core Rule Set
#   - Apache moved to port 8080 (localhost only)
#   - Rate limiting and connection limits
#   - Cross-distro support (Debian/Ubuntu, RHEL/Fedora, Alpine)
#   - Rollback capability
#   - Dry-run mode
#
# Usage:
#   sudo ./apache_waf_proxy.sh [OPTIONS]
#
# Options:
#   --install         Install and configure HAProxy + Coraza WAF
#   --uninstall       Remove WAF stack and restore Apache to port 80
#   --status          Show current status of services
#   --test-waf        Test WAF with sample attack patterns
#   --dry-run         Show what would be done without making changes
#   --detection-only  Enable WAF in detection-only mode (log but don't block)
#   --paranoia N      Set OWASP CRS paranoia level (1-4, default: 2)
#   --apache-port N   Set Apache backend port (default: 8080)
#   -h, --help        Show this help message
#
# Author: Security Toolkit
# License: MIT
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly BACKUP_DIR="/var/backups/security/waf_proxy"
readonly LOG_FILE="/var/log/waf_proxy_install.log"
readonly CORAZA_SPOA_VERSION="v0.5.0"
readonly CORAZA_SPOA_DIR="/opt/coraza-spoa"
readonly CORAZA_CONF_DIR="/etc/coraza-spoa"
readonly CRS_VERSION="v4.0.0"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly TIMESTAMP

# Defaults
APACHE_BACKEND_PORT=8080
WAF_PARANOIA_LEVEL=2
DETECTION_ONLY=false
DRY_RUN=false

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------
setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    exec > >(tee -a "$LOG_FILE") 2>&1
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%H:%M:%S') $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%H:%M:%S') $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" >&2
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $(date '+%H:%M:%S') $*"
}

#-------------------------------------------------------------------------------
# System Detection
#-------------------------------------------------------------------------------
detect_system() {
    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
        APACHE_SERVICE="apache2"
        APACHE_CONF_DIR="/etc/apache2"
        APACHE_PORTS_CONF="/etc/apache2/ports.conf"
        APACHE_SITES_DIR="/etc/apache2/sites-available"
        HAPROXY_SERVICE="haproxy"
        DISTRO_FAMILY="debian"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf check-update || true"
        APACHE_SERVICE="httpd"
        APACHE_CONF_DIR="/etc/httpd"
        APACHE_PORTS_CONF="/etc/httpd/conf/httpd.conf"
        APACHE_SITES_DIR="/etc/httpd/conf.d"
        HAPROXY_SERVICE="haproxy"
        DISTRO_FAMILY="rhel"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum check-update || true"
        APACHE_SERVICE="httpd"
        APACHE_CONF_DIR="/etc/httpd"
        APACHE_PORTS_CONF="/etc/httpd/conf/httpd.conf"
        APACHE_SITES_DIR="/etc/httpd/conf.d"
        HAPROXY_SERVICE="haproxy"
        DISTRO_FAMILY="rhel"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
        PKG_INSTALL="apk add"
        PKG_UPDATE="apk update"
        APACHE_SERVICE="apache2"
        APACHE_CONF_DIR="/etc/apache2"
        APACHE_PORTS_CONF="/etc/apache2/httpd.conf"
        APACHE_SITES_DIR="/etc/apache2/conf.d"
        HAPROXY_SERVICE="haproxy"
        DISTRO_FAMILY="alpine"
    else
        log_error "Unsupported distribution. Supported: Debian/Ubuntu, RHEL/Fedora/CentOS, Alpine"
        exit 1
    fi

    # Detect init system
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="sysvinit"
    fi

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
    esac

    log_info "Detected: $DISTRO_FAMILY family, $PKG_MGR package manager, $INIT_SYSTEM init, $ARCH arch"
}

#-------------------------------------------------------------------------------
# Service Management
#-------------------------------------------------------------------------------
service_cmd() {
    local action="$1"
    local service="$2"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would $action $service"
        return 0
    fi

    case "$INIT_SYSTEM" in
        systemd)
            systemctl "$action" "$service"
            ;;
        openrc)
            # Map systemd actions to OpenRC equivalents
            case "$action" in
                is-active)
                    rc-service "$service" status &>/dev/null
                    ;;
                *)
                    rc-service "$service" "$action"
                    ;;
            esac
            ;;
        sysvinit)
            # Map systemd actions to SysVinit equivalents
            case "$action" in
                is-active)
                    service "$service" status &>/dev/null
                    ;;
                *)
                    service "$service" "$action"
                    ;;
            esac
            ;;
    esac
}

service_enable() {
    local service="$1"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would enable $service"
        return 0
    fi

    case "$INIT_SYSTEM" in
        systemd)
            systemctl enable "$service"
            ;;
        openrc)
            rc-update add "$service" default
            ;;
    esac
}

#-------------------------------------------------------------------------------
# Prerequisite Checks
#-------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

prompt_stats_password() {
    if [[ "$DRY_RUN" == true ]]; then
        STATS_PASSWORD="dryrun-placeholder"
        return 0
    fi

    echo ""
    log_warn "========================================================================="
    log_warn "HAProxy stats page requires a password."
    log_warn "Set an EXTREMELY SECURE one-time password. This password will be stored"
    log_warn "in /etc/haproxy/haproxy.cfg in plain text, so treat it as a one-time"
    log_warn "credential used only for this stats interface."
    log_warn "========================================================================="
    echo ""

    local password=""
    local password_confirm=""
    while true; do
        read -r -s -p "Enter HAProxy stats password: " password
        echo ""
        if [[ -z "$password" ]]; then
            log_error "Password cannot be empty"
            continue
        fi
        if [[ ${#password} -lt 12 ]]; then
            log_error "Password must be at least 12 characters"
            continue
        fi
        read -r -s -p "Confirm password: " password_confirm
        echo ""
        if [[ "$password" != "$password_confirm" ]]; then
            log_error "Passwords do not match"
            continue
        fi
        break
    done

    STATS_PASSWORD="$password"
    log_info "Stats password set"
}

check_apache_running() {
    if ! service_cmd is-active "$APACHE_SERVICE" &>/dev/null; then
        if ! pgrep -E "^(apache2|httpd)$" &>/dev/null; then
            log_error "Apache is not running. Please start Apache first."
            exit 1
        fi
    fi
    log_info "Apache is running"
}

#-------------------------------------------------------------------------------
# Backup Functions
#-------------------------------------------------------------------------------
create_backup() {
    log_step "Creating backup of current configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would create backup in $BACKUP_DIR/$TIMESTAMP"
        return 0
    fi

    mkdir -p "$BACKUP_DIR/$TIMESTAMP"

    # Backup Apache config
    if [[ -d "$APACHE_CONF_DIR" ]]; then
        cp -a "$APACHE_CONF_DIR" "$BACKUP_DIR/$TIMESTAMP/apache_conf"
    fi

    # Backup HAProxy config if exists
    if [[ -f /etc/haproxy/haproxy.cfg ]]; then
        cp /etc/haproxy/haproxy.cfg "$BACKUP_DIR/$TIMESTAMP/"
    fi

    # Backup Coraza config if exists
    if [[ -d "$CORAZA_CONF_DIR" ]]; then
        cp -a "$CORAZA_CONF_DIR" "$BACKUP_DIR/$TIMESTAMP/coraza_conf"
    fi

    # Save current state
    cat > "$BACKUP_DIR/$TIMESTAMP/state.txt" << EOF
timestamp=$TIMESTAMP
apache_service=$APACHE_SERVICE
apache_port_original=80
apache_port_new=$APACHE_BACKEND_PORT
distro_family=$DISTRO_FAMILY
EOF

    log_info "Backup created: $BACKUP_DIR/$TIMESTAMP"
}

restore_backup() {
    local backup_path="$1"

    if [[ ! -d "$backup_path" ]]; then
        log_error "Backup not found: $backup_path"
        return 1
    fi

    log_step "Restoring from backup: $backup_path"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would restore from $backup_path"
        return 0
    fi

    # Stop services
    service_cmd stop "$HAPROXY_SERVICE" 2>/dev/null || true
    service_cmd stop coraza-spoa 2>/dev/null || true

    # Restore Apache config
    if [[ -d "$backup_path/apache_conf" ]]; then
        rm -rf "$APACHE_CONF_DIR"
        cp -a "$backup_path/apache_conf" "$APACHE_CONF_DIR"
    fi

    # Restart Apache
    service_cmd restart "$APACHE_SERVICE"

    log_info "Restore complete"
}

#-------------------------------------------------------------------------------
# Installation Functions
#-------------------------------------------------------------------------------
install_packages() {
    log_step "Installing required packages..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would install: haproxy, curl, tar"
        return 0
    fi

    $PKG_UPDATE
    $PKG_INSTALL haproxy curl tar

    log_info "Base packages installed"
}

install_coraza_spoa() {
    log_step "Installing Coraza SPOA WAF agent..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would download and install Coraza SPOA $CORAZA_SPOA_VERSION"
        return 0
    fi

    # Create dedicated user for Coraza SPOA
    if ! id coraza &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin coraza
    fi

    # Create directories
    mkdir -p "$CORAZA_SPOA_DIR"
    mkdir -p "$CORAZA_CONF_DIR"
    mkdir -p /var/log/coraza-spoa

    # Create log files with proper ownership (Coraza needs write access)
    touch /var/log/coraza-spoa/spoa.log
    touch /var/log/coraza-spoa/audit.log
    touch /var/log/coraza-spoa/debug.log
    chown -R coraza:coraza /var/log/coraza-spoa

    # Download Coraza SPOA binary
    local download_url="https://github.com/corazawaf/coraza-spoa/releases/download/${CORAZA_SPOA_VERSION}/coraza-spoa_Linux_${ARCH}.tar.gz"

    log_info "Downloading Coraza SPOA from: $download_url"

    if ! curl -fsSL "$download_url" -o /tmp/coraza-spoa.tar.gz; then
        log_warn "Failed to download pre-built binary, attempting to build from source..."
        install_coraza_spoa_from_source
        return
    fi

    # Extract binary
    tar -xzf /tmp/coraza-spoa.tar.gz -C "$CORAZA_SPOA_DIR"
    chmod +x "$CORAZA_SPOA_DIR/coraza-spoa"
    rm -f /tmp/coraza-spoa.tar.gz

    # Create symlink
    ln -sf "$CORAZA_SPOA_DIR/coraza-spoa" /usr/local/bin/coraza-spoa

    log_info "Coraza SPOA installed to $CORAZA_SPOA_DIR"
}

install_coraza_spoa_from_source() {
    log_step "Building Coraza SPOA from source..."

    # Install Go if not present
    if ! command -v go &>/dev/null; then
        log_info "Installing Go..."
        case "$DISTRO_FAMILY" in
            debian)
                $PKG_INSTALL golang-go git make
                ;;
            rhel)
                $PKG_INSTALL golang git make
                ;;
            alpine)
                $PKG_INSTALL go git make
                ;;
        esac
    fi

    # Clone and build
    local build_dir="/tmp/coraza-spoa-build"
    rm -rf "$build_dir"
    if ! git clone --depth 1 --branch "$CORAZA_SPOA_VERSION" \
        https://github.com/corazawaf/coraza-spoa.git "$build_dir" 2>/dev/null; then
        local vendor_src
        vendor_src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../vendor/coraza-spoa/source"
        if [[ -d "$vendor_src" ]]; then
            log_info "Git clone failed. Using vendored local copy..."
            cp -r "$vendor_src" "$build_dir"
        else
            log_error "Failed to clone coraza-spoa and no vendor copy found."
            return 1
        fi
    fi

    (cd "$build_dir" && go run mage.go build)

    # Binary is output to build/ subdirectory
    cp "$build_dir/build/coraza-spoa" "$CORAZA_SPOA_DIR/"
    chmod +x "$CORAZA_SPOA_DIR/coraza-spoa"
    ln -sf "$CORAZA_SPOA_DIR/coraza-spoa" /usr/local/bin/coraza-spoa

    rm -rf "$build_dir"

    log_info "Coraza SPOA built and installed"
}

install_owasp_crs() {
    log_step "Installing OWASP Core Rule Set..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would download OWASP CRS $CRS_VERSION"
        return 0
    fi

    local crs_dir="$CORAZA_CONF_DIR/coreruleset"

    # Download CRS
    rm -rf "$crs_dir"
    mkdir -p "$crs_dir"

    if curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
        -o /tmp/crs.tar.gz 2>/dev/null; then
        tar -xzf /tmp/crs.tar.gz -C "$crs_dir" --strip-components=1
        rm -f /tmp/crs.tar.gz
    else
        local vendor_crs
        vendor_crs="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../vendor/owasp-crs/coreruleset-${CRS_VERSION}.tar.gz"
        if [[ -f "$vendor_crs" ]]; then
            log_info "CRS download failed. Using vendored local copy..."
            tar -xzf "$vendor_crs" -C "$crs_dir" --strip-components=1
        else
            log_error "Failed to download CRS and no vendor copy found."
            return 1
        fi
    fi

    # Copy example setup to active config
    cp "$crs_dir/crs-setup.conf.example" "$CORAZA_CONF_DIR/crs-setup.conf"

    log_info "OWASP CRS $CRS_VERSION installed"
}

configure_apache_port() {
    log_step "Configuring Apache to listen on port $APACHE_BACKEND_PORT..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would change Apache from port 80 to port $APACHE_BACKEND_PORT"
        return 0
    fi

    case "$DISTRO_FAMILY" in
        debian)
            # Update ports.conf - match Listen 80, Listen 0.0.0.0:80, Listen [::]:80, etc.
            if [[ -f "$APACHE_PORTS_CONF" ]]; then
                sed -i -E "s/^Listen[[:space:]]+(\[?[^]]*\]?:)?80$/Listen 127.0.0.1:$APACHE_BACKEND_PORT/" "$APACHE_PORTS_CONF"
            fi

            # Update default site
            if [[ -f "$APACHE_SITES_DIR/000-default.conf" ]]; then
                sed -i "s/<VirtualHost \*:80>/<VirtualHost 127.0.0.1:$APACHE_BACKEND_PORT>/" \
                    "$APACHE_SITES_DIR/000-default.conf"
            fi

            # Update any other sites
            for site in "$APACHE_SITES_DIR"/*.conf; do
                if [[ -f "$site" ]]; then
                    sed -i "s/<VirtualHost \*:80>/<VirtualHost 127.0.0.1:$APACHE_BACKEND_PORT>/g" "$site"
                fi
            done
            ;;
        rhel)
            # Update main config - match Listen 80, Listen 0.0.0.0:80, etc.
            if [[ -f "$APACHE_PORTS_CONF" ]]; then
                sed -i -E "s/^Listen[[:space:]]+(\[?[^]]*\]?:)?80$/Listen 127.0.0.1:$APACHE_BACKEND_PORT/" "$APACHE_PORTS_CONF"
            fi

            # Update virtual hosts
            for conf in "$APACHE_SITES_DIR"/*.conf; do
                if [[ -f "$conf" ]]; then
                    sed -i "s/<VirtualHost \*:80>/<VirtualHost 127.0.0.1:$APACHE_BACKEND_PORT>/g" "$conf"
                fi
            done
            ;;
        alpine)
            if [[ -f "$APACHE_PORTS_CONF" ]]; then
                sed -i -E "s/^Listen[[:space:]]+(\[?[^]]*\]?:)?80$/Listen 127.0.0.1:$APACHE_BACKEND_PORT/" "$APACHE_PORTS_CONF"
            fi
            ;;
    esac

    log_info "Apache configured to listen on 127.0.0.1:$APACHE_BACKEND_PORT"
}

configure_coraza_spoa() {
    log_step "Configuring Coraza SPOA..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would create Coraza SPOA configuration"
        return 0
    fi

    # Determine SecRuleEngine setting
    local rule_engine="On"
    if [[ "$DETECTION_ONLY" == true ]]; then
        rule_engine="DetectionOnly"
    fi

    # Create main Coraza configuration
    cat > "$CORAZA_CONF_DIR/coraza.conf" << EOF
# Coraza WAF Configuration 
# Generated: $(date)
# WAF Engine: Coraza (https://coraza.io)

# Enable Coraza WAF
SecRuleEngine $rule_engine

# Request body handling
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# Response body handling
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^[45]"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/coraza-spoa/audit.log

# Debug log (level 0 = disabled, 9 = max)
SecDebugLog /var/log/coraza-spoa/debug.log
SecDebugLogLevel 0

# Argument separator
SecArgumentSeparator &
SecCookieFormat 0
EOF

    # Create CRS setup configuration with paranoia level
    cat > "$CORAZA_CONF_DIR/crs-setup.conf" << EOF
# OWASP CRS Setup for Coraza
# Generated: $(date)

# CRS setup version marker - required for CRS rules to recognize setup is loaded
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=400"

# Paranoia Level (1-4)
# 1 = Low false positives, basic protection
# 2 = Moderate protection
# 3 = High protection, more false positives
# 4 = Maximum protection, expect tuning needed
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=$WAF_PARANOIA_LEVEL"

# Sampling percentage (100 = all requests analyzed)
SecAction "id:900010,phase:1,pass,t:none,nolog,setvar:tx.sampling_percentage=100"

# Anomaly scoring mode (recommended)
SecAction "id:900100,phase:1,pass,t:none,nolog,\
  setvar:tx.blocking_paranoia_level=$WAF_PARANOIA_LEVEL"

# Anomaly score thresholds
SecAction "id:900110,phase:1,pass,t:none,nolog,\
  setvar:tx.inbound_anomaly_score_threshold=5,\
  setvar:tx.outbound_anomaly_score_threshold=4"

# Allowed HTTP methods
SecAction "id:900200,phase:1,pass,t:none,nolog,\
  setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"

# Allowed content types
SecAction "id:900220,phase:1,pass,t:none,nolog,\
  setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|'"

# Max file upload size (default 1GB)
SecAction "id:900340,phase:1,pass,t:none,nolog,setvar:tx.max_file_size=1073741824"

# Max combined file upload size
SecAction "id:900350,phase:1,pass,t:none,nolog,setvar:tx.combined_file_sizes=1073741824"
EOF

    # Create SPOA daemon configuration
    cat > "$CORAZA_CONF_DIR/config.yaml" << EOF
# Coraza SPOA Configuration
# Generated: $(date)

bind: 127.0.0.1:9000

log_level: info
log_file: /var/log/coraza-spoa/spoa.log
log_format: json

applications:
  - name: haproxy
    log_level: info
    log_file: /dev/stdout
    log_format: json
    directives: |
      Include $CORAZA_CONF_DIR/coraza.conf
      Include $CORAZA_CONF_DIR/crs-setup.conf
      Include $CORAZA_CONF_DIR/coreruleset/rules/*.conf
    response_check: true
    transaction_ttl_ms: 60000
EOF

    log_info "Coraza SPOA configured with paranoia level $WAF_PARANOIA_LEVEL"
}

configure_haproxy() {
    log_step "Configuring HAProxy with SPOE filter..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would create HAProxy configuration"
        return 0
    fi

    mkdir -p /etc/haproxy
    mkdir -p /run/haproxy

    # Create SPOE configuration for Coraza
    cat > /etc/haproxy/coraza.cfg << 'EOF'
# HAProxy SPOE Configuration for Coraza WAF
# https://github.com/corazawaf/coraza-spoa

[coraza]
spoe-agent coraza-agent
    messages coraza-req
    option var-prefix coraza
    option set-on-error error
    timeout hello      2s
    timeout idle       2m
    timeout processing 500ms
    use-backend coraza-spoa
    log global

spoe-message coraza-req
    args app=str(haproxy) src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body
    event on-frontend-http-request
EOF

    # Create main HAProxy configuration
    cat > /etc/haproxy/haproxy.cfg << EOF
#===============================================================================
# HAProxy Configuration WAF Reverse Proxy with Coraza
# Generated: $(date)
# WAF: Coraza SPOA (https://coraza.io)
#===============================================================================

global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Security hardening
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  http-server-close
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

    # Error files (included only if the default error directory exists)
EOF

    # Conditionally add errorfile directives if the distro ships them
    if [[ -d /etc/haproxy/errors ]] && ls /etc/haproxy/errors/*.http &>/dev/null; then
        for errfile in /etc/haproxy/errors/*.http; do
            local code
            code="$(basename "$errfile" .http)"
            echo "    errorfile $code $errfile" >> /etc/haproxy/haproxy.cfg
        done
    fi

    cat >> /etc/haproxy/haproxy.cfg << EOF

#-------------------------------------------------------------------------------
# Frontend - Public facing (port 80) with Coraza WAF
#-------------------------------------------------------------------------------
frontend http_front
    bind *:80

    # Unique ID for request tracking
    unique-id-format %{+X}o\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid
    unique-id-header X-Request-ID

    #---------------------------------------------------------------------------
    # Fast-path blocking (before WAF for performance)
    #---------------------------------------------------------------------------
    # Block sensitive file extensions
    acl sensitive_ext path_end .sql .bak .old .orig .save .swp .env .htaccess .htpasswd .config .log
    http-request deny deny_status 403 if sensitive_ext

    # Block hidden files/directories (paths containing /.)
    acl hidden_path path_sub /.
    http-request deny deny_status 403 if hidden_path

    # Block common probe/debug files
    acl probe_files path_end phpinfo.php info.php test.php adminer.php
    http-request deny deny_status 403 if probe_files

    #---------------------------------------------------------------------------
    # Coraza WAF (SPOE filter)
    #---------------------------------------------------------------------------
    # SPOE filter for Coraza WAF
    filter spoe engine coraza config /etc/haproxy/coraza.cfg

    # Block requests that Coraza flagged as malicious
    # Coraza SPOA sets txn.coraza.action to "deny" when request should be blocked
    http-request deny deny_status 403 if { var(txn.coraza.action) -m str deny }
    http-response deny deny_status 502 if { var(txn.coraza.action) -m str deny }

    #---------------------------------------------------------------------------
    # Rate limiting
    #---------------------------------------------------------------------------
    stick-table type ip size 100k expire 30s store http_req_rate(10s),conn_cur
    http-request track-sc0 src
    # Block if more than 100 requests per 10 seconds
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
    # Block if more than 50 concurrent connections per IP
    http-request deny deny_status 429 if { sc_conn_cur(0) gt 50 }

    #---------------------------------------------------------------------------
    # Security headers
    #---------------------------------------------------------------------------
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy strict-origin-when-cross-origin
    http-response set-header Permissions-Policy "geolocation=(), microphone=(), camera=()"
    http-response set-header X-Permitted-Cross-Domain-Policies none
    http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"

    # Remove server version disclosure
    http-response del-header Server
    http-response del-header X-Powered-By
    http-response set-header Server "Secure-Proxy"

    default_backend apache_backend

#-------------------------------------------------------------------------------
# Backend - Coraza SPOA agent (WAF processing)
#-------------------------------------------------------------------------------
backend coraza-spoa
    mode tcp
    server coraza 127.0.0.1:9000 check inter 5s

#-------------------------------------------------------------------------------
# Backend - Apache web server
#-------------------------------------------------------------------------------
backend apache_backend
    balance roundrobin
    option forwardfor except 127.0.0.0/8
    option httpchk GET /
    http-check expect rstatus ^[23]

    # Backend server - Apache on localhost
    server apache 127.0.0.1:$APACHE_BACKEND_PORT check inter 5s fall 3 rise 2

    # Retry on connection failure
    retries 3
    option redispatch

#-------------------------------------------------------------------------------
# Statistics page (localhost only for security)
#-------------------------------------------------------------------------------
listen stats
    bind 127.0.0.1:8404
    mode http
    stats enable
    stats uri /haproxy-stats
    stats refresh 10s
    stats admin if LOCALHOST
    stats auth admin:${STATS_PASSWORD}
EOF

    # Set permissions - restrict haproxy.cfg since it contains the stats password
    chmod 640 /etc/haproxy/haproxy.cfg
    chown root:haproxy /etc/haproxy/haproxy.cfg 2>/dev/null || true
    chown haproxy:haproxy /run/haproxy 2>/dev/null || true

    log_info "HAProxy configuration created with Coraza SPOE filter"
}

create_systemd_service() {
    log_step "Creating Coraza SPOA systemd service..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would create systemd service"
        return 0
    fi

    if [[ "$INIT_SYSTEM" != "systemd" ]]; then
        log_warn "Non-systemd system detected, creating init script instead"
        create_init_script
        return
    fi

    cat > /etc/systemd/system/coraza-spoa.service << EOF
[Unit]
Description=Coraza SPOA WAF Agent
Documentation=https://coraza.io
After=network.target
Before=haproxy.service

[Service]
Type=simple
ExecStart=/usr/local/bin/coraza-spoa -config $CORAZA_CONF_DIR/config.yaml
Restart=on-failure
RestartSec=5
User=coraza
Group=coraza

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/coraza-spoa

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service created"
}

create_init_script() {
    # For OpenRC/SysVinit systems
    cat > /etc/init.d/coraza-spoa << 'EOF'
#!/sbin/openrc-run

name="coraza-spoa"
description="Coraza SPOA WAF Agent"
command="/usr/local/bin/coraza-spoa"
command_args="-config /etc/coraza-spoa/config.yaml"
command_background=true
pidfile="/run/${name}.pid"
output_log="/var/log/coraza-spoa/spoa.log"
error_log="/var/log/coraza-spoa/spoa.log"

depend() {
    need net
    before haproxy
}
EOF
    chmod +x /etc/init.d/coraza-spoa
}

harden_apache() {
    log_step "Hardening Apache configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would harden Apache configuration"
        return 0
    fi

    case "$DISTRO_FAMILY" in
        debian)
            # Create security configuration
            cat > /etc/apache2/conf-available/security-hardening.conf << 'EOF'
# Security Hardening Configuration
# Generated by WAF Proxy Setup Script

# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable directory browsing globally
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/>
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Protect sensitive files
<FilesMatch "\.(sql|bak|old|orig|save|swp|env|git|htaccess|htpasswd|ini|log|conf)$">
    Require all denied
</FilesMatch>

# Block access to hidden files/directories
<DirectoryMatch "/\.">
    Require all denied
</DirectoryMatch>

# Disable TRACE method
TraceEnable Off

# Prevent clickjacking (backup - also set in HAProxy)
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
EOF
            a2enconf security-hardening 2>/dev/null || true
            a2enmod headers 2>/dev/null || true
            ;;
        rhel)
            # Append to main httpd.conf or create security conf
            cat > /etc/httpd/conf.d/security-hardening.conf << 'EOF'
# Security Hardening Configuration
# Generated by WAF Proxy Setup Script

ServerTokens Prod
ServerSignature Off

<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<FilesMatch "\.(sql|bak|old|orig|save|swp|env|git|htaccess|htpasswd|ini|log|conf)$">
    Require all denied
</FilesMatch>

<DirectoryMatch "/\.">
    Require all denied
</DirectoryMatch>

TraceEnable Off

<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
EOF
            ;;
        alpine)
            # Alpine uses httpd.conf directly
            if ! grep -q "ServerTokens Prod" "$APACHE_PORTS_CONF" 2>/dev/null; then
                cat >> "$APACHE_PORTS_CONF" << 'EOF'

# Security Hardening
ServerTokens Prod
ServerSignature Off
TraceEnable Off
EOF
            fi
            ;;
    esac

    log_info "Apache hardening applied"
}

harden_php() {
    log_step "Hardening PHP configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would harden PHP configuration"
        return 0
    fi

    local php_ini_files=()

    # Find PHP ini files based on distro
    case "$DISTRO_FAMILY" in
        debian)
            # Check for PHP-FPM and Apache module configs
            for ini in /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini; do
                [[ -f "$ini" ]] && php_ini_files+=("$ini")
            done
            ;;
        rhel)
            [[ -f /etc/php.ini ]] && php_ini_files+=("/etc/php.ini")
            ;;
        alpine)
            for ini in /etc/php*/php.ini; do
                [[ -f "$ini" ]] && php_ini_files+=("$ini")
            done
            ;;
    esac

    if [[ ${#php_ini_files[@]} -eq 0 ]]; then
        log_warn "No PHP ini files found, skipping PHP hardening"
        return 0
    fi

    for ini in "${php_ini_files[@]}"; do
        log_info "Hardening $ini"

        # Hide PHP version
        sed -i 's/^expose_php.*/expose_php = Off/' "$ini"
        if ! grep -q "^expose_php" "$ini"; then
            echo "expose_php = Off" >> "$ini"
        fi

        # Secure session cookies
        sed -i 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' "$ini"
        if ! grep -q "^session.cookie_httponly" "$ini"; then
            echo "session.cookie_httponly = 1" >> "$ini"
        fi

        sed -i 's/^;*session.cookie_samesite.*/session.cookie_samesite = Lax/' "$ini"
        if ! grep -q "^session.cookie_samesite" "$ini"; then
            echo "session.cookie_samesite = Lax" >> "$ini"
        fi

        # Disable dangerous functions (optional - uncomment if needed)
        # sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen/' "$ini"
    done

    log_info "PHP hardening applied"
}

#-------------------------------------------------------------------------------
# Main Operations
#-------------------------------------------------------------------------------
do_install() {
    log_info "=============================================="
    log_info "Installing HAProxy + Coraza WAF Reverse Proxy"
    log_info "=============================================="

    prompt_stats_password
    check_apache_running
    create_backup
    install_packages
    install_coraza_spoa
    install_owasp_crs
    configure_coraza_spoa
    configure_apache_port
    configure_haproxy
    create_systemd_service
    harden_apache
    harden_php

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Installation simulation complete"
        return 0
    fi

    # Validate HAProxy config
    log_step "Validating HAProxy configuration..."
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1; then
        log_error "HAProxy configuration validation failed!"
        log_warn "Restoring backup..."
        restore_backup "$BACKUP_DIR/$TIMESTAMP"
        exit 1
    fi

    # Start services
    log_step "Starting services..."
    service_cmd restart "$APACHE_SERVICE"

    # Start Coraza SPOA first
    service_enable coraza-spoa
    service_cmd start coraza-spoa
    sleep 2

    # Then start HAProxy
    service_enable "$HAPROXY_SERVICE"
    service_cmd restart "$HAPROXY_SERVICE"

    # Wait for services to start
    sleep 3

    # Verify
    log_step "Verifying installation..."
    local errors=0

    if ! ss -tlnp | grep -q ":80 "; then
        log_error "HAProxy is not listening on port 80"
        errors=$((errors + 1))
    fi

    if ! ss -tlnp | grep -q ":9000 "; then
        log_error "Coraza SPOA is not listening on port 9000"
        errors=$((errors + 1))
    fi

    if ! ss -tlnp | grep -q ":$APACHE_BACKEND_PORT "; then
        log_error "Apache is not listening on port $APACHE_BACKEND_PORT"
        errors=$((errors + 1))
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Installation verification failed with $errors errors"
        exit 1
    fi

    echo ""
    log_info "=============================================="
    log_info "WAF Reverse Proxy installed successfully!"
    log_info "=============================================="
    echo ""
    log_info "Architecture:"
    log_info "  Client -> HAProxy (port 80) -> Coraza WAF -> Apache (port $APACHE_BACKEND_PORT)"
    echo ""
    log_info "WAF Engine: Coraza (https://coraza.io)"
    log_info "WAF Mode: $([ "$DETECTION_ONLY" == true ] && echo "Detection Only (logging)" || echo "Blocking")"
    log_info "Paranoia Level: $WAF_PARANOIA_LEVEL"
    echo ""
    log_info "HAProxy stats: http://localhost:8404/haproxy-stats"
    log_info "  Username: admin"
    log_info "  Password: (the password you set during install)"
    echo ""
    log_info "Logs:"
    log_info "  HAProxy:     /var/log/haproxy.log"
    log_info "  Coraza WAF:  /var/log/coraza-spoa/audit.log"
    log_info "  Coraza SPOA: /var/log/coraza-spoa/spoa.log"
    echo ""
    log_info "To test WAF: $0 --test-waf"
    log_info "To uninstall: $0 --uninstall"
}

do_uninstall() {
    log_info "Uninstalling WAF Reverse Proxy..."

    # Find latest backup
    local latest_backup
    latest_backup=$(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)

    if [[ -z "$latest_backup" ]]; then
        log_error "No backup found for restoration"
        log_warn "Manual restoration required:"
        log_warn "  1. Edit Apache config to listen on port 80"
        log_warn "  2. Stop services: systemctl stop haproxy coraza-spoa"
        exit 1
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would restore from: $latest_backup"
        return 0
    fi

    # Stop services
    service_cmd stop "$HAPROXY_SERVICE" 2>/dev/null || true
    service_cmd stop coraza-spoa 2>/dev/null || true

    # Disable services
    case "$INIT_SYSTEM" in
        systemd)
            systemctl disable coraza-spoa 2>/dev/null || true
            ;;
        openrc)
            rc-update del coraza-spoa default 2>/dev/null || true
            ;;
    esac

    # Restore Apache configuration
    restore_backup "$latest_backup"

    # Restart Apache on original port
    service_cmd restart "$APACHE_SERVICE"

    log_info "WAF Reverse Proxy removed. Apache restored to port 80."
}

do_status() {
    log_info "Service Status:"
    echo ""

    echo "Coraza SPOA (WAF Agent):"
    if service_cmd is-active coraza-spoa &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Port: 9000"
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "HAProxy (Reverse Proxy):"
    if service_cmd is-active "$HAPROXY_SERVICE" &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Listening on:"
        ss -tlnp | grep haproxy | awk '{print "    " $4}'
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "Apache ($APACHE_SERVICE):"
    if service_cmd is-active "$APACHE_SERVICE" &>/dev/null || pgrep -E "^(apache2|httpd)$" &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Listening on:"
        ss -tlnp | grep -E "apache|httpd" | awk '{print "    " $4}'
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "Port Summary:"
    echo "  Port 80 (HAProxy):   $(ss -tlnp | grep -q ':80 ' && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
    echo "  Port 9000 (Coraza):  $(ss -tlnp | grep -q ':9000 ' && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
    echo "  Port $APACHE_BACKEND_PORT (Apache): $(ss -tlnp | grep -q ":$APACHE_BACKEND_PORT " && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
}

do_test_waf() {
    log_info "Testing Coraza WAF rules..."
    echo ""

    local base_url="http://127.0.0.1"
    local tests_passed=0
    local tests_failed=0

    # Test 1: Normal request (should pass)
    echo -n "Test 1 - Normal request: "
    local normal_code
    normal_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url/" 2>/dev/null || echo "000")
    if [[ "$normal_code" =~ ^[23] ]]; then
        echo -e "${GREEN}PASS${NC} ($normal_code)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}FAIL${NC} (Got: $normal_code)"
        tests_failed=$((tests_failed + 1))
    fi

    # Test 2: SQL Injection attempt (should block with OWASP CRS)
    echo -n "Test 2 - SQL Injection: "
    local sqli_code
    sqli_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url/?id=1'%20OR%20'1'='1" 2>/dev/null || echo "000")
    if [[ "$sqli_code" == "403" ]]; then
        echo -e "${GREEN}BLOCKED${NC} (403 Forbidden)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}NOT BLOCKED${NC} (Got: $sqli_code)"
        tests_failed=$((tests_failed + 1))
    fi

    # Test 3: XSS attempt
    echo -n "Test 3 - XSS Attack: "
    local xss_code
    xss_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url/?q=<script>alert(1)</script>" 2>/dev/null || echo "000")
    if [[ "$xss_code" == "403" ]]; then
        echo -e "${GREEN}BLOCKED${NC} (403 Forbidden)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}NOT BLOCKED${NC} (Got: $xss_code)"
        tests_failed=$((tests_failed + 1))
    fi

    # Test 4: Path traversal
    echo -n "Test 4 - Path Traversal: "
    local traversal_code
    traversal_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url/../../../etc/passwd" 2>/dev/null || echo "000")
    if [[ "$traversal_code" == "403" ]]; then
        echo -e "${GREEN}BLOCKED${NC} (403 Forbidden)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}NOT BLOCKED${NC} (Got: $traversal_code)"
        tests_failed=$((tests_failed + 1))
    fi

    # Test 5: Remote Command Execution attempt
    echo -n "Test 5 - RCE Attempt: "
    local rce_code
    rce_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url/?cmd=;cat%20/etc/passwd" 2>/dev/null || echo "000")
    if [[ "$rce_code" == "403" ]]; then
        echo -e "${GREEN}BLOCKED${NC} (403 Forbidden)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}NOT BLOCKED${NC} (Got: $rce_code)"
        tests_failed=$((tests_failed + 1))
    fi

    # Test 6: Protocol attack (HTTP request smuggling attempt)
    echo -n "Test 6 - Invalid HTTP: "
    local smuggle_code
    smuggle_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Transfer-Encoding: chunked, chunked" "$base_url/" 2>/dev/null || echo "000")
    if [[ "$smuggle_code" == "403" ]] || [[ "$smuggle_code" == "400" ]]; then
        echo -e "${GREEN}BLOCKED${NC} ($smuggle_code)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}NOT BLOCKED${NC} (Got: $smuggle_code)"
        tests_failed=$((tests_failed + 1))
    fi

    echo ""
    echo "=============================================="
    echo -e "Results: ${GREEN}$tests_passed passed${NC}, ${YELLOW}$tests_failed need review${NC}"
    echo "=============================================="

    if [[ "$DETECTION_ONLY" == true ]]; then
        echo ""
        echo -e "${YELLOW}Note: WAF is in DETECTION-ONLY mode${NC}"
        echo "Attacks are logged but not blocked."
        echo "Check logs: /var/log/coraza-spoa/audit.log"
    fi

    echo ""
    echo "WAF Engine: Coraza (https://coraza.io)"
    echo "Ruleset: OWASP CRS $CRS_VERSION"
    echo "Paranoia Level: $WAF_PARANOIA_LEVEL"
}

show_help() {
    cat << EOF
Apache WAF Reverse Proxy Setup Script

Deploys HAProxy + Coraza WAF in front of Apache web servers.
Coraza is a modern, actively maintained OWASP ModSecurity replacement
with full OWASP Core Rule Set v4 compatibility.

Usage: $SCRIPT_NAME [OPTIONS]

Options:
  --install         Install and configure HAProxy + Coraza WAF
  --uninstall       Remove WAF stack and restore Apache to port 80
  --status          Show current status of all services
  --test-waf        Test WAF with sample attack patterns
  --dry-run         Show what would be done without making changes
  --detection-only  Enable WAF in detection-only mode (log but don't block)
  --paranoia N      Set OWASP CRS paranoia level (1-4, default: 2)
                      1 = Low false positives, basic protection
                      2 = Moderate protection (default)
                      3 = High protection, more false positives
                      4 = Maximum protection, expect tuning needed
  --apache-port N   Set Apache backend port (default: 8080)
  -h, --help        Show this help message

Examples:
  # Install with default settings
  sudo $SCRIPT_NAME --install

  # Install in detection-only mode first (recommended for tuning)
  sudo $SCRIPT_NAME --install --detection-only

  # Install with higher security (paranoia level 3)
  sudo $SCRIPT_NAME --install --paranoia 3

  # Preview changes without installing
  sudo $SCRIPT_NAME --install --dry-run

  # Check status of all services
  sudo $SCRIPT_NAME --status

  # Test WAF rules with attack patterns
  sudo $SCRIPT_NAME --test-waf

  # Remove and restore original configuration
  sudo $SCRIPT_NAME --uninstall

Architecture after installation:
  Internet -> HAProxy (port 80) -> Coraza WAF (SPOA) -> Apache (port 8080)

WAF Engine: Coraza (https://coraza.io)
  - Modern OWASP ModSecurity replacement
  - Full OWASP Core Rule Set v4 compatibility
  - Better accuracy and actively maintained

EOF
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    local action=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install)
                action="install"
                shift
                ;;
            --uninstall)
                action="uninstall"
                shift
                ;;
            --status)
                action="status"
                shift
                ;;
            --test-waf)
                action="test"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --detection-only)
                DETECTION_ONLY=true
                shift
                ;;
            --paranoia)
                if [[ $# -lt 2 ]]; then
                    log_error "--paranoia requires a value (1-4)"
                    exit 1
                fi
                WAF_PARANOIA_LEVEL="$2"
                if [[ ! "$WAF_PARANOIA_LEVEL" =~ ^[1-4]$ ]]; then
                    log_error "Paranoia level must be 1-4"
                    exit 1
                fi
                shift 2
                ;;
            --apache-port)
                if [[ $# -lt 2 ]]; then
                    log_error "--apache-port requires a port number"
                    exit 1
                fi
                APACHE_BACKEND_PORT="$2"
                if [[ ! "$APACHE_BACKEND_PORT" =~ ^[0-9]+$ ]]; then
                    log_error "Invalid port number"
                    exit 1
                fi
                shift 2
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

    if [[ -z "$action" ]]; then
        show_help
        exit 0
    fi

    # Setup
    check_root
    setup_logging
    detect_system

    # Execute action
    case "$action" in
        install)
            do_install
            ;;
        uninstall)
            do_uninstall
            ;;
        status)
            do_status
            ;;
        test)
            do_test_waf
            ;;
    esac
}

main "$@"
