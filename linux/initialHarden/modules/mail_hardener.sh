#!/usr/bin/env bash
# ==============================================================================
# Script Name: mail_hardener.sh
# Description: Unified mail server hardener for Postfix + Dovecot (+ Roundcube)
#              Supports both Debian/Ubuntu and Fedora/RHEL systems
# Author: Security Team
# Date: 2025-2026
# Version: 3.2
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

# --- Global Variables ---
SECURITY_LEVEL=""  # Will be set by prompt: "strict" or "relaxed"

# --- Utility Functions ---
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; }

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "\033[0;31m[ERROR]\033[0m Must be run as root" >&2
        exit 1
    fi
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
    INITIAL_BACKUP_FILE="$BACKUP_DIR/mail_backup_initial.tar.gz"
    POST_HARDENING_BACKUP_FILE="$BACKUP_DIR/mail_backup_post_hardening.tar.gz"

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

# --- SSL/Auth Security Level Prompt ---
prompt_security_level() {
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET}  ${MAGENTA}Dovecot/POP3 Security Configuration${RESET}                     ${YELLOW}│${RESET}"
    echo -e "${YELLOW}├─────────────────────────────────────────────────────────────┤${RESET}"
    echo -e "${YELLOW}│${RESET}  Choose your security level for Dovecot:                   ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}                                                             ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}  ${GREEN}[1] Strict Security (Recommended)${RESET}                       ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}      - SSL/TLS required for all connections                ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}      - Plaintext authentication disabled                   ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}      - Best security, but requires SSL setup               ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}                                                             ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}  ${BLUE}[2] Relaxed Security${RESET}                                    ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}      - SSL/TLS available but not required                  ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}      - Plaintext authentication allowed                    ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}      - Better compatibility, lower security                ${YELLOW}│${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    while true; do
        read -p "$(echo -e "${BLUE}Enter your choice (1 or 2): ${RESET}")" -r choice
        case "$choice" in
            1)
                SECURITY_LEVEL="strict"
                info "Selected: Strict Security (SSL required, plaintext auth disabled)"
                break
                ;;
            2)
                SECURITY_LEVEL="relaxed"
                info "Selected: Relaxed Security (SSL optional, plaintext auth allowed)"
                break
                ;;
            *)
                warn "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# --- SSL Certificate Generation ---
generate_certs() {
    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        info "SSL certificates already exist"
        
        # Verify and fix permissions on existing certificates
        chown root:dovecot "$KEY_FILE" 2>/dev/null || chown root:root "$KEY_FILE"
        chmod 640 "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        
        # Fix SELinux context if SELinux is enabled
        if command -v restorecon &>/dev/null && getenforce &>/dev/null; then
            restorecon -v "$CERT_FILE" "$KEY_FILE" 2>/dev/null || true
        fi
        
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
    
    # Set proper ownership and permissions
    # dovecot group needs to read the private key
    chown root:dovecot "$KEY_FILE" 2>/dev/null || chown root:root "$KEY_FILE"
    chmod 640 "$KEY_FILE"  # Owner read/write, group read
    chmod 644 "$CERT_FILE"  # World readable
    
    # Set correct SELinux context
    if command -v restorecon &>/dev/null && getenforce &>/dev/null; then
        restorecon -v "$CERT_FILE" "$KEY_FILE" 2>/dev/null || true
        ok "SELinux contexts set for certificates"
    fi
    
    ok "Self-signed certificates generated with correct permissions"
}

harden_dovecot_debian() {
    # SSL configuration
    if [[ -f "$DOVECOT_SSL_CONF" ]] && ! grep -q "# === Mail Hardener" "$DOVECOT_SSL_CONF" 2>/dev/null; then
        # Generate certs with proper permissions
        generate_certs
        
        # Determine SSL and auth settings based on security level
        local ssl_setting="yes"
        local plaintext_auth="no"
        local ssl_comment="SSL enabled but not required - allows both encrypted and plain connections"
        local auth_comment="Plaintext auth allowed for scoring compatibility"
        
        if [[ "$SECURITY_LEVEL" == "strict" ]]; then
            ssl_setting="required"
            plaintext_auth="yes"
            ssl_comment="SSL required for all connections"
            auth_comment="Plaintext auth disabled for maximum security"
        fi
        
        cat >> "$DOVECOT_SSL_CONF" <<EOF

# === Mail Hardener: SSL/TLS Configuration ===
# $ssl_comment
ssl = $ssl_setting
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_cert = <$CERT_FILE
ssl_key = <$KEY_FILE
EOF
    fi

    # Auth configuration
    if [[ -f "$DOVECOT_AUTH_CONF" ]] && ! grep -q "# === Mail Hardener" "$DOVECOT_AUTH_CONF" 2>/dev/null; then
        local plaintext_auth="no"
        local auth_comment="Plaintext auth allowed for scoring compatibility"
        
        if [[ "$SECURITY_LEVEL" == "strict" ]]; then
            plaintext_auth="yes"
            auth_comment="Plaintext auth disabled for maximum security"
        fi
        
        cat >> "$DOVECOT_AUTH_CONF" <<EOF

# === Mail Hardener: Authentication Security ===
# $auth_comment
disable_plaintext_auth = $plaintext_auth
auth_mechanisms = plain login

# === Mail Hardener: Brute Force Protection ===
auth_failure_delay = 3 secs
mail_max_userip_connections = 10
EOF
    fi

    # Postfix SASL auth socket - modify existing service auth block or add config
    local master_conf="/etc/dovecot/conf.d/10-master.conf"
    if [[ -f "$master_conf" ]] && ! grep -q "# === Mail Hardener: Postfix Auth" "$master_conf" 2>/dev/null; then
        # Ensure postfix user can access the socket
        mkdir -p /var/spool/postfix/private

        if grep -q "^service auth {" "$master_conf" 2>/dev/null; then
            # Existing service auth block found -- inject unix_listener inside it
            # to avoid duplicate service auth blocks that break Dovecot
            if ! grep -q "var/spool/postfix/private/auth" "$master_conf" 2>/dev/null; then
                sed -i '/^service auth {/a\  # === Mail Hardener: Postfix Auth Socket ===\n  unix_listener /var/spool/postfix/private/auth {\n    mode = 0660\n    user = postfix\n    group = postfix\n  }' "$master_conf"
                info "Injected Postfix auth socket into existing Dovecot service auth block"
            else
                info "Postfix auth socket already configured in Dovecot"
            fi
        else
            # No existing service auth block -- append a new one
            cat >> "$master_conf" <<'EOF'

# === Mail Hardener: Postfix Auth Socket ===
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
            info "Configured Dovecot auth socket for Postfix SASL"
        fi
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
        # Ensure postfix spool directory exists for auth socket
        mkdir -p /var/spool/postfix/private

        # Generate certificates with proper permissions
        generate_certs

        # Determine SSL and auth settings based on security level
        local ssl_setting="yes"
        local plaintext_auth="no"
        local ssl_comment="SSL enabled but not required - allows both encrypted and plain connections"
        local auth_comment="Plaintext auth allowed for scoring compatibility"
        
        if [[ "$SECURITY_LEVEL" == "strict" ]]; then
            ssl_setting="required"
            plaintext_auth="yes"
            ssl_comment="SSL required for all connections"
            auth_comment="Plaintext auth disabled for maximum security"
        fi

        cat >> "$dovecot_local" <<EOF

# === Mail Hardener: SSL/TLS Configuration ===
# $ssl_comment
ssl = $ssl_setting
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_prefer_server_ciphers = yes
ssl_cert = <$CERT_FILE
ssl_key = <$KEY_FILE

# === Mail Hardener: Authentication Security ===
# $auth_comment
disable_plaintext_auth = $plaintext_auth
auth_mechanisms = plain login
mail_privileged_group = mail

# === Mail Hardener: Brute Force Protection ===
auth_failure_delay = 3 secs
mail_max_userip_connections = 10

# === Mail Hardener: Information Disclosure Prevention ===
login_greeting = Dovecot ready.

# === Mail Hardener: AD/SSSD userdb override ===
userdb {
  driver = passwd
  args = username_format=%n
}
EOF

        # Configure Postfix auth socket in 10-master.conf to avoid duplicate service auth blocks
        local master_conf="/etc/dovecot/conf.d/10-master.conf"
        if [[ -f "$master_conf" ]] && grep -q "^service auth {" "$master_conf" 2>/dev/null; then
            # Inject into existing service auth block
            if ! grep -q "var/spool/postfix/private/auth" "$master_conf" 2>/dev/null; then
                sed -i '/^service auth {/a\  # === Mail Hardener: Postfix Auth Socket ===\n  unix_listener /var/spool/postfix/private/auth {\n    mode = 0660\n    user = postfix\n    group = postfix\n  }' "$master_conf"
            fi
        else
            # No 10-master.conf or no service auth block -- add to local.conf
            cat >> "$dovecot_local" <<'EOF'

# === Mail Hardener: Postfix Auth Socket ===
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
        fi
        info "Configured Dovecot hardening and Postfix SASL auth socket"
    fi
}

# --- Initial Backup (before hardening) ---
backup_initial_configs() {
    # Check if initial backup already exists
    if [[ -f "$INITIAL_BACKUP_FILE" ]]; then
        warn "Initial backup already exists at $INITIAL_BACKUP_FILE"
        warn "Skipping backup to preserve original configuration"
        return 0
    fi

    mkdir -p "$BACKUP_DIR"
    info "Creating initial backup at $INITIAL_BACKUP_FILE..."
    local backup_paths=()
    
    # Only backup files that actually exist
    [[ -d /etc/postfix ]] && backup_paths+=("etc/postfix")
    [[ -d /etc/dovecot ]] && backup_paths+=("etc/dovecot")
    [[ -d /etc/roundcubemail ]] && backup_paths+=("etc/roundcubemail")
    [[ -f /etc/httpd/conf.d/roundcubemail.conf ]] && backup_paths+=("etc/httpd/conf.d/roundcubemail.conf")

    if [[ ${#backup_paths[@]} -gt 0 ]]; then
        # Store paths relative to root for easy restoration
        tar -czpf "$INITIAL_BACKUP_FILE" -C / "${backup_paths[@]}" 2>/dev/null && ok "Initial backup complete" || { error "Initial backup failed"; exit 1; }
    else
        warn "No mail configs found to backup"
    fi
}

# --- Post-Hardening Backup ---
backup_post_hardening() {
    mkdir -p "$BACKUP_DIR"
    info "Creating post-hardening backup at $POST_HARDENING_BACKUP_FILE..."
    local backup_paths=()
    
    # Only backup files that actually exist
    [[ -d /etc/postfix ]] && backup_paths+=("etc/postfix")
    [[ -d /etc/dovecot ]] && backup_paths+=("etc/dovecot")
    [[ -d /etc/roundcubemail ]] && backup_paths+=("etc/roundcubemail")
    [[ -f /etc/httpd/conf.d/roundcubemail.conf ]] && backup_paths+=("etc/httpd/conf.d/roundcubemail.conf")

    if [[ ${#backup_paths[@]} -gt 0 ]]; then
        # Store paths relative to root for easy restoration
        tar -czpf "$POST_HARDENING_BACKUP_FILE" -C / "${backup_paths[@]}" 2>/dev/null && ok "Post-hardening backup complete" || { warn "Post-hardening backup failed"; }
    else
        warn "No mail configs found to backup"
    fi
}

# --- Rollback ---
rollback_initial() {
    if [[ ! -f "$INITIAL_BACKUP_FILE" ]]; then
        error "Initial backup not found at $INITIAL_BACKUP_FILE"
        error "Cannot rollback - no original configuration saved"
        exit 1
    fi
    
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET}  ${RED}WARNING: ROLLBACK OPERATION${RESET}                               ${YELLOW}│${RESET}"
    echo -e "${YELLOW}├─────────────────────────────────────────────────────────────┤${RESET}"
    echo -e "${YELLOW}│${RESET}  This will restore your mail server to its original        ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}  pre-hardening configuration by replacing all hardened     ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}  files with the initial backup.                            ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}                                                             ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}  Backup to restore: ${GREEN}$INITIAL_BACKUP_FILE${RESET}${YELLOW}"
    # Calculate padding for alignment
    local padding=$((60 - ${#INITIAL_BACKUP_FILE} - 19))
    printf "${YELLOW}%*s│${RESET}\n" "$padding" ""
    echo -e "${YELLOW}│${RESET}                                                             ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}  Services will be stopped and restarted during rollback.   ${YELLOW}│${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    read -p "$(echo -e "${RED}Are you sure you want to proceed? ${RESET}(yes/no): ")" -r response
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$response" != "yes" && "$response" != "y" ]]; then
        info "Rollback cancelled"
        exit 0
    fi
    
    info "Starting rollback from $INITIAL_BACKUP_FILE..."
    
    # Stop services before restoration
    info "Stopping mail services..."
    for svc in "${SERVICES[@]}"; do
        if command -v systemctl &>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || warn "Could not stop $svc"
        fi
    done
    
    # Remove existing configuration directories to ensure clean restoration
    info "Removing current hardened configurations..."
    [[ -d /etc/postfix ]] && rm -rf /etc/postfix && ok "Removed /etc/postfix"
    [[ -d /etc/dovecot ]] && rm -rf /etc/dovecot && ok "Removed /etc/dovecot"
    [[ -d /etc/roundcubemail ]] && rm -rf /etc/roundcubemail && ok "Removed /etc/roundcubemail"
    [[ -f /etc/httpd/conf.d/roundcubemail.conf ]] && rm -f /etc/httpd/conf.d/roundcubemail.conf && ok "Removed /etc/httpd/conf.d/roundcubemail.conf"
    
    # Extract backup to root directory (this will restore the original files)
    info "Restoring original configuration files..."
    tar -xzpf "$INITIAL_BACKUP_FILE" -C / 2>/dev/null && ok "Configuration files restored" || { 
        error "Rollback failed - could not extract backup"
        exit 1
    }
    
    # Fix ownership and permissions after restoration
    info "Fixing ownership and permissions..."
    [[ -d /etc/postfix ]] && chown -R root:root /etc/postfix && chmod -R u=rwX,go=rX /etc/postfix && ok "Fixed /etc/postfix permissions"
    [[ -d /etc/dovecot ]] && chown -R root:root /etc/dovecot && chmod -R u=rwX,go=rX /etc/dovecot && ok "Fixed /etc/dovecot permissions"
    [[ -d /etc/roundcubemail ]] && chown -R root:root /etc/roundcubemail && ok "Fixed /etc/roundcubemail permissions"

    # Restart services
    info "Restarting mail services..."
    for svc in "${SERVICES[@]}"; do
        restart_service "$svc"
    done
    
    ok "${GREEN}Rollback complete!${RESET}"
    info "Your mail server has been restored to its original configuration"
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
    for conf in /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-master.conf /etc/dovecot/local.conf; do
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

# === Mail Hardener: SASL Authentication (via Dovecot) ===
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

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

# --- Roundcube Hardening (RHEL/Fedora only) ---
harden_roundcube() {
    [[ "$OS_FAMILY" != "rhel" ]] && return 0
    [[ ! -f "$ROUNDCUBE_CONFIG" ]] && { info "Roundcube not installed, skipping"; return 0; }

    info "Hardening Roundcube..."
    cp "$ROUNDCUBE_CONFIG" "${ROUNDCUBE_CONFIG}.hardening-backup"

    # Check and create temp/logs directories if they don't exist
    if [[ -n "$ROUNDCUBE_DIR" ]]; then
        if [[ ! -d "$ROUNDCUBE_DIR/temp" ]]; then
            info "Creating $ROUNDCUBE_DIR/temp directory..."
            mkdir -p "$ROUNDCUBE_DIR/temp"
            ok "Created temp directory"
        fi
        
        if [[ ! -d "$ROUNDCUBE_DIR/logs" ]]; then
            info "Creating $ROUNDCUBE_DIR/logs directory..."
            mkdir -p "$ROUNDCUBE_DIR/logs"
            ok "Created logs directory"
        fi
    fi

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

# --- Main ---
require_root
detect_os
setup_paths

case "${1:-}" in
    --rollback)
        rollback_initial
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
        backup_initial_configs
        
        # Backup individual config directories
        info "Creating individual config backups..."
        [[ -d /etc/dovecot ]] && cp -a /etc/dovecot/ /var/backups/mail_hardener/ && ok "Dovecot config backed up"
        [[ -d /etc/postfix ]] && cp -a /etc/postfix/ /var/backups/mail_hardener/ && ok "Postfix config backed up"
        [[ -d /etc/roundcubemail ]] && cp -a /etc/roundcubemail/ /var/backups/mail_hardener/ && ok "Roundcube config backed up"
        
        # Prompt for security level before hardening
        prompt_security_level
        
        harden_postfix
        harden_dovecot
        harden_roundcube
        
        # Create post-hardening backup
        backup_post_hardening
        
        ok "${GREEN}Mail hardening complete!${RESET}"
        info "Initial backup saved at: $INITIAL_BACKUP_FILE"
        info "Post-hardening backup saved at: $POST_HARDENING_BACKUP_FILE"
        info "To rollback to original configuration, run: $0 --rollback; To restore the dovecot config, run: sudo cp -a /var/backups/mail_hardener/dovecot/* /etc/dovecot/ Then run: sudo chown -R root:root /etc/dovecot Then run: sudo chmod -R u=rwX,go=rX /etc/dovecot Then run: systemctl restart dovecot"
        info ""
        info "Verify services:"
        info "  systemctl status postfix dovecot"
        [[ "$OS_FAMILY" == "rhel" ]] && info "  systemctl status httpd"
        ;;
esac
