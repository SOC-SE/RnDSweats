#!/usr/bin/env bash
#
# OpenCart Hardening & Management Script (Ubuntu)
#
# DESCRIPTION:
#   This script manages and hardens an OpenCart installation and its dependent services
#   on Ubuntu. It is designed to be SAFE and INTERACTIVE by default. Still needs more work and testing.
#
# FEATURES:
#   1. Backup:
#      - Creates a backup of OpenCart files, web server configs, PHP configs, and the DB.
#   2. Hardening:
#      - Applies opinionated hardening to OpenCart, web server (Apache/Nginx), PHP, and DB.
#   3. Rollback:
#      - Restores a previous backup (files + DB) if something goes wrong.
#   4. Test Setup:
#      - Installs a full OpenCart stack for testing.
#      - If an existing install is detected, it can wipe files and drop the DB (with strong confirmation).
#   5. Status:
#      - Shows the status of OpenCart and dependent services.
#
# USAGE (run as root):
#   ./opencart_hardener.sh --backup
#   ./opencart_hardener.sh --harden
#   ./opencart_hardener.sh --rollback
#   ./opencart_hardener.sh --test-setup
#   ./opencart_hardener.sh --status
#
# NOTES:
#   - This script MUST be run as root.
#   - All destructive actions are gated behind explicit, interactive confirmations.
#   - Backups are stored under BACKUP_ROOT (see config section below).

# Hardening the script does:

# Web Server (Apache/Nginx):
# Adds security headers (X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy)
# Disables directory listing
# Tightens SSL/TLS protocols (disables SSLv3, TLSv1, TLSv1.1) and cipher suites

# PHP:
# Disables expose_php to hide PHP version
# Turns off display_errors and enables log_errors
# Sets disable_functions to block dangerous calls (exec, system, passthru, shell_exec, etc.)
# Sets open_basedir to restrict filesystem access to the web root
# Disables allow_url_fopen and allow_url_include to prevent remote file inclusion
# Enables session.cookie_httponly, session.cookie_secure, and session.use_strict_mode

# Database (MySQL/MariaDB):
# Binds database to localhost only (127.0.0.1) to prevent remote access

# OpenCart Files:
# Sets ownership to www-data
# Restricts file permissions (750 for directories, 640 for files)
# Allows write access only to specific directories (storage, image, themes)

# OS-Level:
# Optionally installs and configures UFW firewall with SSH, HTTP, HTTPS rules

#

set -euo pipefail

#######################################
# CONFIGURATION (EDIT AS NEEDED)
#######################################

# Default OpenCart directory
OPENCART_DIR="/var/www/opencart"

# Default DB settings (used for backup/restore and test setup)
OPENCART_DB_NAME="opencart"
OPENCART_DB_USER="opencart_user"
OPENCART_DB_HOST="localhost"

# Backup root directory
BACKUP_ROOT="/var/backups/opencart-hardening"

# Minimum PHP version required for OpenCart
# shellcheck disable=SC2034  # Used in detect_php for version checking
MIN_PHP_VERSION="7.4"

#######################################
# COLORS & LOGGING
#######################################

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }

confirm() {
    local prompt="$1"
    # Non-interactive mode: auto-confirm
    if [[ "${HARDEN_NONINTERACTIVE:-0}" == "1" ]]; then
        return 0
    fi
    local reply
    echo
    read -r -p "$prompt [y/N]: " reply || true
    case "$reply" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) log_info "Cancelled."; return 1 ;;
    esac
}

confirm_danger() {
    local prompt="$1"
    local token="$2"
    # Non-interactive mode: auto-confirm
    if [[ "${HARDEN_NONINTERACTIVE:-0}" == "1" ]]; then
        return 0
    fi
    local reply
    echo
    log_warn "$prompt"
    read -r -p "Type '${token}' to confirm: " reply || true
    if [[ "$reply" != "$token" ]]; then
        log_info "Confirmation token mismatch. Cancelled."
        return 1
    fi
    return 0
}

#######################################
# ROOT CHECK
#######################################

if [[ "$EUID" -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
fi

#######################################
# DETECTION HELPERS
#######################################

WEB_SERVER=""   # apache|nginx|unknown
DB_SERVER=""    # mysql|mariadb|unknown
PHP_SAPI=""     # apache2|fpm|cli|unknown
PHP_VERSION_DETECTED=""

detect_web_server() {
    if systemctl is-active --quiet apache2 2>/dev/null || command -v apache2 >/dev/null 2>&1; then
        WEB_SERVER="apache"
    elif systemctl is-active --quiet nginx 2>/dev/null || command -v nginx >/dev/null 2>&1; then
        WEB_SERVER="nginx"
    else
        WEB_SERVER="unknown"
    fi
    log_info "Detected web server: ${WEB_SERVER}"
}

detect_db_server() {
    if systemctl is-active --quiet mariadb 2>/dev/null || command -v mariadb >/dev/null 2>&1; then
        DB_SERVER="mariadb"
    elif systemctl is-active --quiet mysql 2>/dev/null || command -v mysql >/dev/null 2>&1; then
        DB_SERVER="mysql"
    else
        DB_SERVER="unknown"
    fi
    log_info "Detected DB server: ${DB_SERVER}"
}

detect_php() {
    if command -v php >/dev/null 2>&1; then
        PHP_VERSION_DETECTED="$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo "")"
    fi

    if systemctl list-units --type=service --state=running --no-legend 2>/dev/null | grep -q 'php.*fpm'; then
        PHP_SAPI="fpm"
    elif [[ "$WEB_SERVER" == "apache" ]] && apache2ctl -M 2>/dev/null | grep -qi "php"; then
        PHP_SAPI="apache2"
    else
        PHP_SAPI="unknown"
    fi

    log_info "Detected PHP: version=${PHP_VERSION_DETECTED:-unknown}, sapi=${PHP_SAPI}"
}

#######################################
# BACKUP FUNCTIONS
#######################################

create_backup() {
    log_info "Creating backup before proceeding..."

    detect_web_server
    detect_db_server
    detect_php

    local ts
    ts="$(date +'%Y-%m-%d_%H-%M-%S')"
    local backup_dir="${BACKUP_ROOT}/${ts}"
    mkdir -p "$backup_dir"

    # Backup OpenCart directory
    if [[ -d "$OPENCART_DIR" ]]; then
        log_info "Backing up OpenCart directory: $OPENCART_DIR"
        tar czf "${backup_dir}/opencart_files.tar.gz" -C "$(dirname "$OPENCART_DIR")" "$(basename "$OPENCART_DIR")"
    else
        log_warn "OpenCart directory not found at ${OPENCART_DIR}, skipping files backup."
    fi

    # Backup web server configs
    case "$WEB_SERVER" in
        apache)
            log_info "Backing up Apache configs..."
            tar czf "${backup_dir}/apache_configs.tar.gz" /etc/apache2 || log_warn "Failed to backup Apache configs."
            ;;
        nginx)
            log_info "Backing up Nginx configs..."
            tar czf "${backup_dir}/nginx_configs.tar.gz" /etc/nginx || log_warn "Failed to backup Nginx configs."
            ;;
        *)
            log_warn "Unknown web server, skipping web server config backup."
            ;;
    esac

    # Backup PHP configs
    if [[ -d /etc/php ]]; then
        log_info "Backing up PHP configs..."
        tar czf "${backup_dir}/php_configs.tar.gz" /etc/php || log_warn "Failed to backup PHP configs."
    fi

    # Backup DB
    if [[ "$DB_SERVER" != "unknown" ]]; then
        log_info "Backing up database '${OPENCART_DB_NAME}'..."
        if command -v mysqldump >/dev/null 2>&1; then
            # Try mysqldump - relies on ~/.my.cnf, socket auth, or passwordless local root
            # Use OpenCart DB credentials if available, otherwise try root
            if [[ -n "${OPENCART_DB_USER:-}" && -n "${OPENCART_DB_PASS:-}" ]]; then
                mysqldump -u "${OPENCART_DB_USER}" -p"${OPENCART_DB_PASS}" "${OPENCART_DB_NAME}" > "${backup_dir}/db_${OPENCART_DB_NAME}.sql" 2>/dev/null \
                    || log_warn "Failed to dump DB ${OPENCART_DB_NAME} with OpenCart credentials."
            elif [[ -f ~/.my.cnf ]]; then
                mysqldump "${OPENCART_DB_NAME}" > "${backup_dir}/db_${OPENCART_DB_NAME}.sql" 2>/dev/null \
                    || log_warn "Failed to dump DB ${OPENCART_DB_NAME} using ~/.my.cnf."
            else
                # Try socket auth (common on modern MySQL/MariaDB for root)
                mysqldump -u root "${OPENCART_DB_NAME}" > "${backup_dir}/db_${OPENCART_DB_NAME}.sql" 2>/dev/null \
                    || log_warn "Failed to dump DB ${OPENCART_DB_NAME}. Configure ~/.my.cnf or run mysqlharden.sh first."
            fi
        else
            log_warn "mysqldump not found, skipping DB backup."
        fi
    else
        log_warn "No DB server detected, skipping DB backup."
    fi

    # Metadata
    cat > "${backup_dir}/manifest.txt" <<EOF
timestamp=${ts}
opencart_dir=${OPENCART_DIR}
db_name=${OPENCART_DB_NAME}
db_user=${OPENCART_DB_USER}
web_server=${WEB_SERVER}
db_server=${DB_SERVER}
php_sapi=${PHP_SAPI}
php_version=${PHP_VERSION_DETECTED}
EOF

    log_success "Backup created at: ${backup_dir}"
    echo "$backup_dir"
}

list_backups() {
    if [[ ! -d "$BACKUP_ROOT" ]]; then
        log_warn "No backups directory found at ${BACKUP_ROOT}."
        return 1
    fi
    find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d | sort
}

#######################################
# HARDENING FUNCTIONS
#######################################

harden_apache() {
    log_info "Applying Apache hardening..."

    local conf_dir="/etc/apache2"
    if [[ ! -d "$conf_dir" ]]; then
        log_warn "Apache config directory not found at ${conf_dir}."
        return
    fi

    a2enmod headers ssl rewrite >/dev/null 2>&1 || true

    # Add security headers via a conf snippet
    local security_conf="${conf_dir}/conf-available/security-opencart.conf"
    cat > "$security_conf" <<'EOF'
# Hide Apache version information
ServerTokens Prod
ServerSignature Off

# Prevent ETag inode leaks
FileETag MTime Size

<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    # Adjust CSP as needed for your site
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
</IfModule>

# Disable directory listing globally
<Directory /var/www/>
    Options -Indexes
</Directory>
EOF

    a2enconf security-opencart >/dev/null 2>&1 || true

    # Also fix the default security.conf if it exists (overrides ServerTokens)
    local default_security="${conf_dir}/conf-available/security.conf"
    if [[ -f "$default_security" ]]; then
        sed -i 's/^ServerTokens .*/ServerTokens Prod/' "$default_security" 2>/dev/null || true
        sed -i 's/^ServerSignature .*/ServerSignature Off/' "$default_security" 2>/dev/null || true
    fi

    # Disable autoindex module (directory listing)
    a2dismod autoindex >/dev/null 2>&1 || true

    # Disable mod_status (information disclosure)
    a2dismod status >/dev/null 2>&1 || true

    # Only touch SSL protocols/ciphers if SSL is already configured
    if grep -Rqi "SSLEngine on" /etc/apache2/sites-enabled 2>/dev/null; then
        log_info "Existing HTTPS detected; tightening SSL protocols/ciphers..."
        local ssl_conf="${conf_dir}/conf-available/ssl-hardening.conf"
        cat > "$ssl_conf" <<'EOF'
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on
EOF
        a2enconf ssl-hardening >/dev/null 2>&1 || true
    else
        log_info "No existing HTTPS config detected; skipping SSL hardening."
    fi

    systemctl reload apache2
    log_success "Apache hardening applied."
}

harden_nginx() {
    log_info "Applying Nginx hardening..."

    local conf_dir="/etc/nginx"
    if [[ ! -d "$conf_dir" ]]; then
        log_warn "Nginx config directory not found at ${conf_dir}."
        return
    fi

    # Global security headers
    local security_conf="${conf_dir}/conf.d/security-opencart.conf"
    cat > "$security_conf" <<'EOF'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
# Adjust CSP as needed for your site
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;
EOF

    # Disable autoindex globally (can be overridden per server)
    local autoindex_conf="${conf_dir}/conf.d/autoindex-off.conf"
    cat > "$autoindex_conf" <<'EOF'
autoindex off;
EOF

    # SSL hardening only if SSL is already used
    if grep -Rqi "ssl_certificate" /etc/nginx/sites-enabled 2>/dev/null; then
        log_info "Existing HTTPS detected; tightening SSL protocols/ciphers..."
        local ssl_conf="${conf_dir}/conf.d/ssl-hardening.conf"
        cat > "$ssl_conf" <<'EOF'
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;
EOF
    else
        log_info "No existing HTTPS config detected; skipping SSL hardening."
    fi

    nginx -t
    systemctl reload nginx
    log_success "Nginx hardening applied."
}

harden_php() {
    log_info "Applying PHP hardening..."

    if [[ ! -d /etc/php ]]; then
        log_warn "PHP config directory /etc/php not found."
        return
    fi

    # Find php.ini files for relevant SAPIs
    local ini_files=()
    case "$PHP_SAPI" in
        fpm)
            ini_files=(/etc/php/*/fpm/php.ini)
            ;;
        apache2)
            ini_files=(/etc/php/*/apache2/php.ini)
            ;;
        *)
            ini_files=(/etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini)
            ;;
    esac

    # Dangerous functions to disable — these are commonly abused by webshells.
    # proc_open is needed by some frameworks (e.g., Composer), but not by OpenCart at runtime.
    local disable_funcs="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec"
    disable_funcs+=",parse_ini_file,show_source,eval,assert,create_function,call_user_func_with_array"

    # Detect web root for open_basedir
    local web_root="/var/www/html"
    [[ -n "${OPENCART_DIR:-}" && -d "$OPENCART_DIR" ]] && web_root="$OPENCART_DIR"
    local open_basedir="${web_root}:/tmp:/usr/share/php"

    for ini in "${ini_files[@]}"; do
        [[ -f "$ini" ]] || continue
        log_info "Hardening $ini"

        # --- Replace existing directives ---
        sed -i 's/^\s*expose_php\s*=.*/expose_php = Off/' "$ini" || true
        sed -i 's/^\s*display_errors\s*=.*/display_errors = Off/' "$ini" || true
        sed -i 's/^\s*log_errors\s*=.*/log_errors = On/' "$ini" || true
        sed -i 's/^\s*allow_url_fopen\s*=.*/allow_url_fopen = Off/' "$ini" || true
        sed -i 's/^\s*allow_url_include\s*=.*/allow_url_include = Off/' "$ini" || true
        sed -i "s|^\s*disable_functions\s*=.*|disable_functions = ${disable_funcs}|" "$ini" || true
        sed -i "s|^\s*open_basedir\s*=.*|open_basedir = ${open_basedir}|" "$ini" || true

        # --- Add if missing ---
        grep -q '^expose_php' "$ini" || echo "expose_php = Off" >> "$ini"
        grep -q '^display_errors' "$ini" || echo "display_errors = Off" >> "$ini"
        grep -q '^log_errors' "$ini" || echo "log_errors = On" >> "$ini"
        grep -q '^allow_url_fopen' "$ini" || echo "allow_url_fopen = Off" >> "$ini"
        grep -q '^allow_url_include' "$ini" || echo "allow_url_include = Off" >> "$ini"
        grep -q '^disable_functions' "$ini" || echo "disable_functions = ${disable_funcs}" >> "$ini"
        grep -q '^open_basedir' "$ini" || echo "open_basedir = ${open_basedir}" >> "$ini"

        # Session security
        sed -i 's/^\s*session\.cookie_httponly\s*=.*/session.cookie_httponly = 1/' "$ini" || true
        sed -i 's/^\s*session\.cookie_secure\s*=.*/session.cookie_secure = 1/' "$ini" || true
        sed -i 's/^\s*session\.use_strict_mode\s*=.*/session.use_strict_mode = 1/' "$ini" || true
        grep -q '^session.cookie_httponly' "$ini" || echo "session.cookie_httponly = 1" >> "$ini"
        grep -q '^session.cookie_secure' "$ini" || echo "session.cookie_secure = 1" >> "$ini"
        grep -q '^session.use_strict_mode' "$ini" || echo "session.use_strict_mode = 1" >> "$ini"
    done

    # Reload PHP services
    local php_fpm_unit
    php_fpm_unit=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | grep -oP 'php[\d.]+-fpm\.service' | head -1)
    if [[ -n "$php_fpm_unit" ]]; then
        systemctl restart "$php_fpm_unit" || true
    fi
    if [[ "$WEB_SERVER" == "apache" ]]; then
        systemctl reload apache2 || true
    fi

    log_success "PHP hardening applied."
}

harden_db() {
    log_info "Applying basic DB hardening (local-only)..."

    if [[ "$DB_SERVER" == "unknown" ]]; then
        log_warn "No DB server detected; skipping DB hardening."
        return
    fi

    local conf_file=""
    if [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]]; then
        conf_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
    elif [[ -f /etc/mysql/mariadb.conf.d/50-server.cnf ]]; then
        conf_file="/etc/mysql/mariadb.conf.d/50-server.cnf"
    fi

    if [[ -n "$conf_file" ]]; then
        log_info "Ensuring DB is bound to localhost in $conf_file"
        if grep -q '^bind-address' "$conf_file"; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$conf_file"
        else
            echo "bind-address = 127.0.0.1" >> "$conf_file"
        fi
        systemctl restart "${DB_SERVER}" || true
        log_success "DB bind-address set to 127.0.0.1."
    else
        log_warn "Could not find mysqld config file; skipping bind-address hardening."
    fi
}

harden_opencart_files() {
    log_info "Applying OpenCart file/permission hardening..."

    if [[ ! -d "$OPENCART_DIR" ]]; then
        log_warn "OpenCart directory not found at ${OPENCART_DIR}, skipping."
        return
    fi

    chown -R www-data:www-data "$OPENCART_DIR"

    # Tighten default permissions
    find "$OPENCART_DIR" -type d -exec chmod 750 {} \;
    find "$OPENCART_DIR" -type f -exec chmod 640 {} \;

    # Writable dirs (adjust as needed)
    for d in system/storage image catalog/view/theme; do
        if [[ -d "$OPENCART_DIR/$d" ]]; then
            chmod -R 770 "$OPENCART_DIR/$d"
        fi
    done

    # Config files
    for f in config.php admin/config.php; do
        if [[ -f "$OPENCART_DIR/$f" ]]; then
            chmod 640 "$OPENCART_DIR/$f"
        fi
    done

    # Remove installer directory (security risk if left accessible)
    if [[ -d "$OPENCART_DIR/install" ]]; then
        rm -rf "$OPENCART_DIR/install"
        log_success "Removed OpenCart installer directory."
    fi

    # Restrict admin panel access by IP (allow only localhost + machine's own subnet)
    local admin_htaccess="$OPENCART_DIR/admin/.htaccess"
    if [[ -d "$OPENCART_DIR/admin" ]]; then
        # Detect the machine's primary non-loopback interface subnet
        local iface_info
        iface_info=$(ip -4 -o addr show scope global | head -1 | awk '{print $4}') # e.g. 172.20.242.17/24
        local machine_ip="${iface_info%%/*}"
        local cidr="${iface_info##*/}"
        # Calculate network address from IP and CIDR
        local subnet_allow=""
        if [[ -n "$machine_ip" && -n "$cidr" ]]; then
            IFS='.' read -r o1 o2 o3 o4 <<< "$machine_ip"
            # Convert CIDR to mask and apply
            local full_mask=$(( 0xFFFFFFFF << (32 - cidr) & 0xFFFFFFFF ))
            local m1=$(( (full_mask >> 24) & 255 ))
            local m2=$(( (full_mask >> 16) & 255 ))
            local m3=$(( (full_mask >> 8) & 255 ))
            local m4=$(( full_mask & 255 ))
            local net="$((o1 & m1)).$((o2 & m2)).$((o3 & m3)).$((o4 & m4))"
            subnet_allow="${net}/${cidr}"
        fi

        cat > "$admin_htaccess" <<HTEOF
# Restrict OpenCart admin panel access
# Auto-detected subnet: ${subnet_allow:-UNKNOWN}
# To change allowed networks, edit this file:
#   ${admin_htaccess}
<IfModule mod_authz_core.c>
    Require ip 127.0.0.1
    Require ip ::1
    Require ip ${subnet_allow:-10.0.0.0/8}
</IfModule>
HTEOF
        chown www-data:www-data "$admin_htaccess"
        chmod 640 "$admin_htaccess"
        log_success "Admin panel restricted to localhost + ${subnet_allow:-FALLBACK 10.0.0.0/8}."
        log_warn "NOTE: OpenCart admin panel is now IP-restricted. To modify allowed networks, edit: ${admin_htaccess}"
    fi

    log_success "OpenCart file/permission hardening applied."
}

run_hardening() {
    log_info "Starting hardening process..."

    local backup_dir
    backup_dir="$(create_backup)"

    if ! confirm "Proceed with hardening using backup at ${backup_dir}?"; then
        return
    fi

    detect_web_server
    detect_db_server
    detect_php

    case "$WEB_SERVER" in
        apache) harden_apache ;;
        nginx)  harden_nginx ;;
        *)      log_warn "Unknown web server; skipping web server hardening." ;;
    esac

    harden_php
    harden_db
    harden_opencart_files

    log_success "Hardening completed."
}

#######################################
# ROLLBACK FUNCTIONS
#######################################

run_rollback() {
    log_info "Rollback selected."

    local backups
    backups="$(list_backups)" || { log_error "No backups found."; return; }

    echo "Available backups:"
    echo "$backups"
    echo
    read -r -p "Enter full path of backup to restore: " chosen || true

    if [[ -z "$chosen" || ! -d "$chosen" ]]; then
        log_error "Invalid backup directory."
        return
    fi

    log_warn "You are about to restore from backup: $chosen"
    log_warn "This may overwrite current configs and database."

    if ! confirm "Continue with rollback?"; then
        return
    fi

    if ! confirm_danger "This will overwrite current OpenCart files and may restore the DB." "ROLLBACK"; then
        return
    fi

    detect_web_server
    detect_db_server

    # Stop services
    case "$WEB_SERVER" in
        apache) systemctl stop apache2 || true ;;
        nginx)  systemctl stop nginx || true ;;
    esac
    if [[ "$DB_SERVER" != "unknown" ]]; then
        systemctl stop "$DB_SERVER" || true
    fi

    # Restore files
    if [[ -f "${chosen}/opencart_files.tar.gz" ]]; then
        log_info "Restoring OpenCart files..."
        tar xzf "${chosen}/opencart_files.tar.gz" -C /
    fi

    if [[ -f "${chosen}/apache_configs.tar.gz" ]]; then
        log_info "Restoring Apache configs..."
        tar xzf "${chosen}/apache_configs.tar.gz" -C /
    fi

    if [[ -f "${chosen}/nginx_configs.tar.gz" ]]; then
        log_info "Restoring Nginx configs..."
        tar xzf "${chosen}/nginx_configs.tar.gz" -C /
    fi

    if [[ -f "${chosen}/php_configs.tar.gz" ]]; then
        log_info "Restoring PHP configs..."
        tar xzf "${chosen}/php_configs.tar.gz" -C /
    fi

    # Restore DB
    if [[ -f "${chosen}/db_${OPENCART_DB_NAME}.sql" && "$DB_SERVER" != "unknown" ]]; then
        if confirm "Restore database '${OPENCART_DB_NAME}' from backup?"; then
            systemctl start "$DB_SERVER" || true
            mysql -e "DROP DATABASE IF EXISTS \`${OPENCART_DB_NAME}\`;"
            mysql -e "CREATE DATABASE \`${OPENCART_DB_NAME}\`;"
            mysql "${OPENCART_DB_NAME}" < "${chosen}/db_${OPENCART_DB_NAME}.sql"
            log_success "Database restored."
        fi
    fi

    # Start services
    if [[ "$DB_SERVER" != "unknown" ]]; then
        systemctl start "$DB_SERVER" || true
    fi
    case "$WEB_SERVER" in
        apache) systemctl start apache2 || true ;;
        nginx)  systemctl start nginx || true ;;
    esac

    log_success "Rollback completed."
}

#######################################
# TEST SETUP FUNCTIONS
#######################################

install_stack_packages() {
    log_info "Installing OpenCart stack packages (Apache, PHP, DB)..."

    detect_web_server
    detect_db_server
    detect_php

    # Web server
    if [[ "$WEB_SERVER" == "unknown" ]]; then
        if confirm "Install Apache as web server?"; then
            apt-get update
            apt-get install -y apache2
            WEB_SERVER="apache"
        elif confirm "Install Nginx as web server instead?"; then
            apt-get update
            apt-get install -y nginx
            WEB_SERVER="nginx"
        else
            log_error "No web server selected; aborting test setup."
            return 1
        fi
    fi

    # DB server
    if [[ "$DB_SERVER" == "unknown" ]]; then
        if confirm "Install MariaDB server?"; then
            apt-get update
            apt-get install -y mariadb-server
            DB_SERVER="mariadb"
        elif confirm "Install MySQL server instead?"; then
            apt-get update
            apt-get install -y mysql-server
            DB_SERVER="mysql"
        else
            log_error "No DB server selected; aborting test setup."
            return 1
        fi
    fi

    # PHP + extensions
    if [[ "$PHP_SAPI" == "unknown" ]]; then
        log_info "Installing PHP and required extensions..."
        apt-get update
        apt-get install -y php php-cli php-common php-mysql php-zip php-gd php-curl php-xml php-mbstring
        if [[ "$WEB_SERVER" == "apache" ]]; then
            apt-get install -y libapache2-mod-php
            PHP_SAPI="apache2"
        else
            apt-get install -y php-fpm
            PHP_SAPI="fpm"
        fi
    fi

    log_success "Stack packages installed."
}

setup_opencart_vhost_apache() {
    log_info "Configuring Apache vhost for OpenCart..."

    local vhost="/etc/apache2/sites-available/opencart.conf"
    cat > "$vhost" <<EOF
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot ${OPENCART_DIR}

    <Directory ${OPENCART_DIR}>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/opencart_error.log
    CustomLog \${APACHE_LOG_DIR}/opencart_access.log combined
</VirtualHost>
EOF

    a2enmod rewrite >/dev/null 2>&1 || true
    a2ensite opencart.conf >/dev/null 2>&1 || true
    a2dissite 000-default.conf >/dev/null 2>&1 || true
    systemctl reload apache2
    log_success "Apache vhost configured."
}

setup_opencart_vhost_nginx() {
    log_info "Configuring Nginx server block for OpenCart..."

    local server_block="/etc/nginx/sites-available/opencart"
    cat > "$server_block" <<EOF
server {
    listen 80;
    server_name localhost;

    root ${OPENCART_DIR};
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico)\$ {
        expires max;
        log_not_found off;
    }
}
EOF

    ln -sf "$server_block" /etc/nginx/sites-enabled/opencart
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl reload nginx
    log_success "Nginx server block configured."
}

download_opencart() {
    log_info "Downloading OpenCart..."

    mkdir -p "$OPENCART_DIR"
    # You can adjust version/URL as needed
    local url="https://github.com/opencart/opencart/releases/download/4.0.2.3/opencart-4.0.2.3.zip"
    local tmp_zip="/tmp/opencart.zip"

    apt-get update
    apt-get install -y unzip curl

    if ! curl -fsSL "$url" -o "$tmp_zip" 2>/dev/null; then
        local vendor_zip
        vendor_zip="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../vendor/opencart/opencart-4.0.2.3.zip"
        if [[ -f "$vendor_zip" ]]; then
            log_info "Download failed. Using vendored local copy..."
            cp "$vendor_zip" "$tmp_zip"
        else
            log_warn "Failed to download OpenCart and no vendor copy found."
            return 1
        fi
    fi
    rm -rf "${OPENCART_DIR:?}/"*
    unzip -q "$tmp_zip" -d /tmp/opencart_extract
    # Adjust if structure changes; many releases have "upload" dir
    if [[ -d /tmp/opencart_extract/upload ]]; then
        mv /tmp/opencart_extract/upload/* "$OPENCART_DIR/"
    else
        mv /tmp/opencart_extract/* "$OPENCART_DIR/"
    fi
    rm -rf /tmp/opencart_extract "$tmp_zip"

    log_success "OpenCart downloaded to ${OPENCART_DIR}."
}

setup_opencart_db() {
    log_info "Setting up OpenCart database..."

    systemctl start "$DB_SERVER" || true

    mysql -e "DROP DATABASE IF EXISTS \`${OPENCART_DB_NAME}\`;"
    mysql -e "CREATE DATABASE \`${OPENCART_DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"

    # Create user with password prompt
    local db_pass
    echo
    read -r -s -p "Enter password to create for DB user '${OPENCART_DB_USER}': " db_pass || true
    echo
    mysql -e "DROP USER IF EXISTS '${OPENCART_DB_USER}'@'${OPENCART_DB_HOST}';"
    mysql -e "CREATE USER '${OPENCART_DB_USER}'@'${OPENCART_DB_HOST}' IDENTIFIED BY '${db_pass}';"
    mysql -e "GRANT ALL PRIVILEGES ON \`${OPENCART_DB_NAME}\`.* TO '${OPENCART_DB_USER}'@'${OPENCART_DB_HOST}';"
    mysql -e "FLUSH PRIVILEGES;"

    log_success "OpenCart DB and user created."
}

run_test_setup() {
    log_info "Starting TEST SETUP mode (for lab/testing only)."

    # Detect existing install
    local existing=false
    if [[ -d "$OPENCART_DIR" ]] && [[ -n "$(ls -A "$OPENCART_DIR" 2>/dev/null || true)" ]]; then
        existing=true
    fi

    detect_db_server

    if $existing || [[ "$DB_SERVER" != "unknown" ]]; then
        log_warn "Existing OpenCart files and/or DB server detected."
        log_warn "Test setup can WIPE OpenCart files and DROP the OpenCart DB (${OPENCART_DB_NAME})."
        if ! confirm "Do you want to proceed with a FRESH test setup (destructive)?"; then
            log_info "Test setup cancelled."
            return
        fi
        if ! confirm_danger "This will delete OpenCart files under ${OPENCART_DIR} and drop DB ${OPENCART_DB_NAME}." "DELETE"; then
            log_info "Test setup cancelled."
            return
        fi
    fi

    # Install stack
    install_stack_packages

    # Wipe existing OpenCart files
    if [[ -d "$OPENCART_DIR" ]]; then
        rm -rf "${OPENCART_DIR:?}/"*
    else
        mkdir -p "$OPENCART_DIR"
    fi

    # Setup DB (drop/create)
    setup_opencart_db

    # Download OpenCart
    download_opencart

    # Configure vhost/server block
    case "$WEB_SERVER" in
        apache) setup_opencart_vhost_apache ;;
        nginx)  setup_opencart_vhost_nginx ;;
        *)      log_warn "Unknown web server; skipping vhost configuration." ;;
    esac

    # Permissions
    harden_opencart_files

    log_success "Test setup completed."
    log_info "You can now access OpenCart via http://localhost/ and complete the web-based installer."
}

#######################################
# STATUS FUNCTION
#######################################

run_status() {
    log_info "Checking status of OpenCart stack..."

    detect_web_server
    detect_db_server
    detect_php

    echo
    echo "Service status:"
    echo "----------------"

    case "$WEB_SERVER" in
        apache)
            systemctl status apache2 --no-pager -l | sed -n '1,5p' || true
            ;;
        nginx)
            systemctl status nginx --no-pager -l | sed -n '1,5p' || true
            ;;
        *)
            log_warn "Web server not detected."
            ;;
    esac

    if [[ "$DB_SERVER" != "unknown" ]]; then
        systemctl status "$DB_SERVER" --no-pager -l | sed -n '1,5p' || true
    else
        log_warn "DB server not detected."
    fi

    # Simple HTTP check
    if command -v curl >/dev/null 2>&1; then
        echo
        log_info "HTTP check to http://localhost/ ..."
        curl -I -s http://localhost/ || log_warn "HTTP check failed."
    fi

    log_success "Status check completed."
}

#######################################
# MAIN ARGUMENT HANDLING
#######################################

usage() {
    cat <<EOF
Usage: $0 [OPTION]

Options:
  --backup       Create a backup of OpenCart and dependent services.
  --harden       Harden OpenCart, web server, PHP, and DB (backup first).
  --rollback     Roll back to a previous backup.
  --test-setup   Install a full OpenCart stack for testing (can wipe existing).
  --status       Show status of OpenCart and dependent services.
  --help         Show this help message.

NOTE: This script must be run as root and is fully interactive by default.
EOF
}

main() {
    local action="${1:-}"

    case "$action" in
        --backup)
            create_backup >/dev/null
            ;;
        --harden)
            run_hardening
            ;;
        --rollback)
            run_rollback
            ;;
        --test-setup)
            run_test_setup
            ;;
        --status)
            run_status
            ;;
        --help|"")
            usage
            ;;
        *)
            log_error "Unknown option: $action"
            usage
            exit 1
            ;;
    esac
}

main "$@"
