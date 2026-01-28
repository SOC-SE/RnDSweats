#!/usr/bin/env bash
# ==============================================================================
# Script Name: mail_hardener.sh
# Description: Unified mail server hardener for Postfix + Dovecot (+ Roundcube)
#              Supports both Debian/Ubuntu and Fedora/RHEL systems
# Author: CCDC Team
# Date: 2025-2026
# Version: 3.0
#
# Usage:
#   ./mail_hardener.sh                # Harden mail services (automatic)
#   ./mail_hardener.sh --rollback     # Rollback to backup
#   ./mail_hardener.sh --test         # Install services first (Fedora)
#   ./mail_hardener.sh --clean        # Clean hardening configs
#
# Supported Systems:
#   - Ubuntu/Debian (apt) - Postfix + Dovecot
#   - Fedora/RHEL (dnf)   - Postfix + Dovecot + Roundcube + Apache
#
# Services Protected: SMTP (25), POP3 (110), IMAP (143), Submission (587)
#
# ==============================================================================

set -euo pipefail

# --- Colors ---
if [[ -t 1 ]] && command -v tput &>/dev/null; then
    RED=$(tput setaf 1 2>/dev/null || echo "")
    GREEN=$(tput setaf 2 2>/dev/null || echo "")
    YELLOW=$(tput setaf 3 2>/dev/null || echo "")
    BLUE=$(tput setaf 4 2>/dev/null || echo "")
    MAGENTA=$(tput setaf 5 2>/dev/null || echo "")
    RESET=$(tput sgr0 2>/dev/null || echo "")
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; RESET=""
fi

# --- Utility Functions ---
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; }

require_root() {
    [[ "$EUID" -ne 0 ]] && { error "Must be run as root"; exit 1; }
}

trap 'error "Unexpected error on line $LINENO"' ERR

# --- OS Detection ---
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        case "$ID" in
            ubuntu|debian|mint|pop) OS_FAMILY="debian" ;;
            fedora|rhel|centos|rocky|alma|ol|oracle) OS_FAMILY="rhel" ;;
            *) OS_FAMILY="unknown" ;;
        esac
    else
        OS_FAMILY="unknown"
        OS_ID="unknown"
    fi
}

# --- Path Configuration (set after OS detection) ---
setup_paths() {
    BACKUP_DIR="/var/backups/mail_hardener"
    TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
    BACKUP_FILE="$BACKUP_DIR/mail_backup_$TIMESTAMP.tar.gz"

    if [[ "$OS_FAMILY" == "debian" ]]; then
        CERT_FILE="/etc/ssl/certs/ssl-cert-snakeoil.pem"
        KEY_FILE="/etc/ssl/private/ssl-cert-snakeoil.key"
        DOVECOT_SSL_CONF="/etc/dovecot/conf.d/10-ssl.conf"
        DOVECOT_AUTH_CONF="/etc/dovecot/conf.d/10-auth.conf"
        WEB_SERVER="apache2"
        WEB_GROUP="www-data"
        SERVICES=(postfix dovecot)
        ROUNDCUBE_CONFIG=""
        ROUNDCUBE_DIR=""
    else
        CERT_FILE="/etc/pki/tls/certs/mail-selfsigned.crt"
        KEY_FILE="/etc/pki/tls/private/mail-selfsigned.key"
        DOVECOT_SSL_CONF="/etc/dovecot/local.conf"
        DOVECOT_AUTH_CONF="/etc/dovecot/local.conf"
        WEB_SERVER="httpd"
        WEB_GROUP="apache"
        SERVICES=(postfix dovecot httpd)
        ROUNDCUBE_CONFIG="/etc/roundcubemail/config.inc.php"
        ROUNDCUBE_DIR="/usr/share/roundcubemail"
    fi
}

# --- Init System Detection ---
restart_service() {
    local svc="$1"
    if command -v systemctl &>/dev/null; then
        systemctl restart "$svc" 2>/dev/null && ok "$svc restarted" || warn "Failed to restart $svc"
    elif command -v rc-service &>/dev/null; then
        rc-service "$svc" restart 2>/dev/null && ok "$svc restarted" || warn "Failed to restart $svc"
    elif command -v service &>/dev/null; then
        service "$svc" restart 2>/dev/null && ok "$svc restarted" || warn "Failed to restart $svc"
    fi
}

enable_service() {
    local svc="$1"
    if command -v systemctl &>/dev/null; then
        systemctl enable "$svc" 2>/dev/null || true
    elif command -v rc-update &>/dev/null; then
        rc-update add "$svc" default 2>/dev/null || true
    fi
}

# --- SSL Certificate Generation ---
generate_certs() {
    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        info "SSL certificates already exist"
        return 0
    fi

    info "Generating self-signed SSL certificates..."
    mkdir -p "$(dirname "$CERT_FILE")" "$(dirname "$KEY_FILE")"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=US/ST=State/L=City/O=Org/CN=mail.local" 2>/dev/null || {
        error "Failed to generate certificates"
        return 1
    }
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    ok "Self-signed certificates generated"
}

# --- Backup ---
backup_configs() {
    mkdir -p "$BACKUP_DIR"
    info "Creating backup at $BACKUP_FILE..."
    local backup_paths=()
    [[ -d /etc/postfix ]] && backup_paths+=("/etc/postfix")
    [[ -d /etc/dovecot ]] && backup_paths+=("/etc/dovecot")
    [[ -d /etc/roundcubemail ]] && backup_paths+=("/etc/roundcubemail")
    [[ -f /etc/httpd/conf.d/roundcubemail.conf ]] && backup_paths+=("/etc/httpd/conf.d/roundcubemail.conf")

    if [[ ${#backup_paths[@]} -gt 0 ]]; then
        tar -czpf "$BACKUP_FILE" "${backup_paths[@]}" 2>/dev/null && ok "Backup complete" || { error "Backup failed"; exit 1; }
    else
        warn "No mail configs found to backup"
    fi
}

# --- Rollback ---
rollback_latest() {
    local latest
    latest="$(find "$BACKUP_DIR" -name "mail_backup_*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
    if [[ -z "$latest" ]]; then
        error "No backups found in $BACKUP_DIR"
        exit 1
    fi
    info "Restoring from $latest..."
    tar -xzpf "$latest" -C / && ok "Restored from backup" || { error "Rollback failed"; exit 1; }

    for svc in "${SERVICES[@]}"; do
        restart_service "$svc"
    done
    ok "Rollback complete"
}

# --- Clean ---
clean_configs() {
    info "Cleaning hardening configurations..."

    for svc in "${SERVICES[@]}"; do
        if command -v systemctl &>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
        fi
    done

    # Clean Postfix
    if [[ -f /etc/postfix/main.cf ]]; then
        sed -i '/# === Mail Hardener/,/^$/d' /etc/postfix/main.cf 2>/dev/null || true
    fi
    if [[ -f /etc/postfix/master.cf ]]; then
        sed -i '/# === Mail Hardener/,/^$/d' /etc/postfix/master.cf 2>/dev/null || true
    fi

    # Clean Dovecot
    for conf in /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/local.conf; do
        [[ -f "$conf" ]] && sed -i '/# === Mail Hardener/,/^$/d' "$conf" 2>/dev/null || true
    done

    # Clean Roundcube
    [[ -f "$ROUNDCUBE_CONFIG" ]] && sed -i '/\/\/ === Mail Hardener/,/^$/d' "$ROUNDCUBE_CONFIG" 2>/dev/null || true

    for svc in "${SERVICES[@]}"; do
        restart_service "$svc"
    done
    ok "Cleanup complete"
}

# --- Postfix Hardening ---
harden_postfix() {
    info "Hardening Postfix..."

    [[ ! -f /etc/postfix/main.cf ]] && { warn "Postfix not installed, skipping"; return 0; }

    # Generate certs if needed
    generate_certs

    # Avoid duplicate hardening
    if grep -q "# === Mail Hardener" /etc/postfix/main.cf 2>/dev/null; then
        info "Postfix already hardened (markers found), skipping"
        return 0
    fi

    cat >> /etc/postfix/main.cf <<EOF

# === Mail Hardener: TLS/SSL Configuration ===
smtpd_tls_security_level = may
smtpd_tls_cert_file = $CERT_FILE
smtpd_tls_key_file = $KEY_FILE
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES
smtp_tls_security_level = may
smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1

# === Mail Hardener: General Security ===
disable_vrfy_command = yes
smtpd_helo_required = yes
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_data_restrictions = reject_unauth_pipelining

EOF

    # Add submission service if not present
    if ! grep -q "^submission inet" /etc/postfix/master.cf 2>/dev/null; then
        cat >> /etc/postfix/master.cf <<'EOF'

# === Mail Hardener: Encrypted submission service ===
submission inet n - n - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
EOF
    fi

    restart_service postfix
}

# --- Dovecot Hardening ---
harden_dovecot() {
    info "Hardening Dovecot..."

    if ! command -v doveconf &>/dev/null && [[ ! -d /etc/dovecot ]]; then
        warn "Dovecot not installed, skipping"
        return 0
    fi

    generate_certs

    if [[ "$OS_FAMILY" == "debian" ]]; then
        harden_dovecot_debian
    else
        harden_dovecot_rhel
    fi

    # Validate config before restart
    if command -v doveconf &>/dev/null; then
        if doveconf -n >/dev/null 2>&1; then
            ok "Dovecot configuration is valid"
        else
            error "Dovecot configuration has errors"
            doveconf -n 2>&1 | head -20 || true
            return 1
        fi
    fi

    restart_service dovecot
}

harden_dovecot_debian() {
    # SSL configuration
    if [[ -f "$DOVECOT_SSL_CONF" ]] && ! grep -q "# === Mail Hardener" "$DOVECOT_SSL_CONF" 2>/dev/null; then
        cat >> "$DOVECOT_SSL_CONF" <<EOF

# === Mail Hardener: SSL/TLS Configuration ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_cert = <$CERT_FILE
ssl_key = <$KEY_FILE
EOF
    fi

    # Auth configuration
    if [[ -f "$DOVECOT_AUTH_CONF" ]] && ! grep -q "# === Mail Hardener" "$DOVECOT_AUTH_CONF" 2>/dev/null; then
        cat >> "$DOVECOT_AUTH_CONF" <<'EOF'

# === Mail Hardener: Authentication Security ===
disable_plaintext_auth = yes
auth_mechanisms = plain login
EOF
    fi
}

harden_dovecot_rhel() {
    local dovecot_local="/etc/dovecot/local.conf"
    [[ ! -f "$dovecot_local" ]] && touch "$dovecot_local"
    cp "$dovecot_local" "${dovecot_local}.hardening-backup" 2>/dev/null || true

    # Add protocols/mail_location if missing
    grep -q "^protocols" /etc/dovecot/dovecot.conf "$dovecot_local" 2>/dev/null || echo "protocols = imap pop3 lmtp" >> "$dovecot_local"
    grep -q "^mail_location" /etc/dovecot/dovecot.conf "$dovecot_local" 2>/dev/null || echo "mail_location = maildir:~/Maildir" >> "$dovecot_local"

    if ! grep -q "# === Mail Hardener" "$dovecot_local" 2>/dev/null; then
        cat >> "$dovecot_local" <<EOF

# === Mail Hardener: SSL/TLS Configuration ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_prefer_server_ciphers = yes
ssl_cert = <$CERT_FILE
ssl_key = <$KEY_FILE

# === Mail Hardener: Authentication Security ===
disable_plaintext_auth = yes
auth_mechanisms = plain login
mail_privileged_group = mail
EOF
    fi
}

# --- Roundcube Hardening (RHEL/Fedora only) ---
harden_roundcube() {
    [[ "$OS_FAMILY" != "rhel" ]] && return 0
    [[ ! -f "$ROUNDCUBE_CONFIG" ]] && { info "Roundcube not installed, skipping"; return 0; }

    info "Hardening Roundcube..."
    cp "$ROUNDCUBE_CONFIG" "${ROUNDCUBE_CONFIG}.hardening-backup"

    # Disable installer
    [[ -d "$ROUNDCUBE_DIR/installer" ]] && chmod 000 "$ROUNDCUBE_DIR/installer" 2>/dev/null || true

    # Security configuration
    if ! grep -q "Mail Hardener" "$ROUNDCUBE_CONFIG" 2>/dev/null; then
        cat >> "$ROUNDCUBE_CONFIG" <<'EOF'

// === Mail Hardener: Security Configuration ===
$config['enable_installer'] = false;
$config['x_frame_options'] = 'sameorigin';
$config['session_lifetime'] = 10;
$config['session_samesite'] = 'Strict';
$config['login_rate_limit'] = 3;
$config['ip_check'] = true;
EOF
    fi

    # Apache security headers
    if [[ -f /etc/httpd/conf.d/roundcubemail.conf ]] && ! grep -q "Header set X-Frame-Options" /etc/httpd/conf.d/roundcubemail.conf; then
        sed -i '/<Directory \/usr\/share\/roundcubemail>/a\    # Security Headers\n    Header set X-Frame-Options "SAMEORIGIN"\n    Header set X-Content-Type-Options "nosniff"\n    Header set X-XSS-Protection "1; mode=block"\n    Header set Referrer-Policy "no-referrer-when-downgrade"' /etc/httpd/conf.d/roundcubemail.conf
    fi

    # File permissions
    chown -R root:"$WEB_GROUP" "$ROUNDCUBE_DIR"
    find "$ROUNDCUBE_DIR" -type f -exec chmod 640 {} \;
    find "$ROUNDCUBE_DIR" -type d -exec chmod 750 {} \;
    chown -R "$WEB_GROUP":"$WEB_GROUP" "$ROUNDCUBE_DIR/temp" "$ROUNDCUBE_DIR/logs"
    chmod 770 "$ROUNDCUBE_DIR/temp" "$ROUNDCUBE_DIR/logs"
    [[ -d /var/lib/roundcubemail ]] && { chown -R "$WEB_GROUP":"$WEB_GROUP" /var/lib/roundcubemail; chmod 750 /var/lib/roundcubemail; }

    # SELinux
    if command -v semanage &>/dev/null && command -v restorecon &>/dev/null; then
        semanage fcontext -a -t httpd_sys_content_t "$ROUNDCUBE_DIR(/.*)?" 2>/dev/null || true
        semanage fcontext -a -t httpd_sys_rw_content_t "$ROUNDCUBE_DIR/temp(/.*)?" 2>/dev/null || true
        semanage fcontext -a -t httpd_sys_rw_content_t "$ROUNDCUBE_DIR/logs(/.*)?" 2>/dev/null || true
        semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/roundcubemail(/.*)?" 2>/dev/null || true
        restorecon -Rv "$ROUNDCUBE_DIR" /var/lib/roundcubemail 2>/dev/null || true
    fi

    restart_service "$WEB_SERVER"
    ok "Roundcube hardened"
}

# --- Firewall Configuration ---
configure_firewall() {
    info "Configuring firewall for mail services..."

    if command -v firewall-cmd &>/dev/null; then
        for svc in smtp smtps imap imaps pop3 pop3s; do
            firewall-cmd --permanent --add-service="$svc" 2>/dev/null || true
        done
        [[ "$OS_FAMILY" == "rhel" ]] && firewall-cmd --permanent --add-service=http 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        ok "firewalld configured"
    elif command -v ufw &>/dev/null; then
        ufw allow 25/tcp 2>/dev/null || true   # SMTP
        ufw allow 110/tcp 2>/dev/null || true  # POP3
        ufw allow 143/tcp 2>/dev/null || true  # IMAP
        ufw allow 587/tcp 2>/dev/null || true  # Submission
        ufw allow 993/tcp 2>/dev/null || true  # IMAPS
        ufw allow 995/tcp 2>/dev/null || true  # POP3S
        ok "ufw configured"
    fi
}

# --- Main ---
require_root
detect_os
setup_paths

case "${1:-}" in
    --rollback)
        rollback_latest
        ;;
    --test)
        if [[ "$OS_FAMILY" == "rhel" ]]; then
            info "Installing mail services on $OS_ID..."
            dnf install -y postfix dovecot 2>&1 | tail -3
            dnf install -y httpd roundcubemail php php-common php-xml php-mbstring php-intl 2>&1 | tail -3 || true
            for svc in "${SERVICES[@]}"; do
                enable_service "$svc"
                restart_service "$svc"
            done
            ok "Services installed. Run without --test to harden."
        else
            info "Installing mail services on $OS_ID..."
            apt-get update -y >/dev/null 2>&1
            apt-get install -y postfix dovecot-core dovecot-imapd dovecot-pop3d 2>&1 | tail -3
            for svc in "${SERVICES[@]}"; do
                enable_service "$svc"
                restart_service "$svc"
            done
            ok "Services installed. Run without --test to harden."
        fi
        ;;
    --clean)
        clean_configs
        ;;
    *)
        info "${MAGENTA}=== Mail Hardener ($OS_ID - $OS_FAMILY) ===${RESET}"
        backup_configs
        harden_postfix
        harden_dovecot
        harden_roundcube
        configure_firewall
        ok "${GREEN}Mail hardening complete!${RESET}"
        info "Backup: $BACKUP_FILE"
        info "Verify services:"
        info "  systemctl status postfix dovecot"
        [[ "$OS_FAMILY" == "rhel" ]] && info "  systemctl status httpd"
        ;;
esac
