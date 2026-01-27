#!/usr/bin/env bash
# ============================================
#   Made with Claude AI
#   Mail Hardener (Postfix + Dovecot + Roundcube)
#   Platform: Fedora
#   Features: Backup, Rollback, TLS Hardening, Testing Mode, Clean
#   Usage:
#     Normal Mode (Harden):  sudo bash mail_hardener_fedora.sh
#     Rollback:              sudo bash mail_hardener_fedora.sh --rollback
#     Testing/Install:       sudo bash mail_hardener_fedora.sh --test
#     Clean Old Configs (mainly use for testing):     sudo bash mail_hardener_fedora.sh --clean

#   *NOTE: Script gets a backup of the initial config, does not take a backup of the hardened config; 
#    to do that, run the hardening script again; however, this will also mess with the rollback option

# Hardening that occurs:
# Postfix Hardening:

# TLS/SSL (Optional):
# Enforces TLS encryption (may level)
# Disables weak protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)
# Uses high-grade ciphers only
# Excludes weak ciphers (aNULL, MD5, RC4, 3DES)
# Adds encrypted submission service on port 587
# General Security:
# Disables VRFY command (prevents email enumeration)
# Requires HELO/EHLO greeting
# Restricts relay to authenticated users only
# Prevents unauthorized pipelining

# Dovecot Hardening:

# TLS/SSL (Optional):
# Requires SSL/TLS for all connections
# Minimum protocol: TLSv1.2
# High-grade cipher suites only
# Server cipher preference enabled
# Authentication Security:
# Disables plaintext authentication (forces encryption)
# Uses plain/login auth mechanisms
# Sets mail privileged group

# Roundcube Hardening:

# Application Security:
# Disables installer (prevents unauthorized access)
# Enables X-Frame-Options (prevents clickjacking)
# Session security with strict SameSite cookies
# Short session lifetime (10 minutes)
# Login rate limiting (3 attempts)
# IP address checking

# Web Server Security (Apache):

# Security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy)
# Denies access to config, temp, and logs directories
# File Permissions:
# Restrictive permissions (640 for files, 750 for directories)
# Proper ownership (root:apache)
# SELinux:
# Proper contexts to prevent 403 errors while maintaining security

# ============================================

set -euo pipefail

# --- Colors (with fallback for non-terminal) ---
if [[ -t 1 ]] && command -v tput &>/dev/null; then
    RED=$(tput setaf 1 2>/dev/null || echo "")
    GREEN=$(tput setaf 2 2>/dev/null || echo "")
    YELLOW=$(tput setaf 3 2>/dev/null || echo "")
    BLUE=$(tput setaf 4 2>/dev/null || echo "")
    CYAN=$(tput setaf 6 2>/dev/null || echo "")
    MAGENTA=$(tput setaf 5 2>/dev/null || echo "")
    RESET=$(tput sgr0 2>/dev/null || echo "")
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; RESET=""
fi

# --- Paths ---
BACKUP_DIR="/var/backups/mail_hardener"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
BACKUP_FILE="$BACKUP_DIR/mail_backup_$TIMESTAMP.tar.gz"
SERVICES=(postfix dovecot httpd)
ROUNDCUBE_CONFIG="/etc/roundcubemail/config.inc.php"
ROUNDCUBE_DIR="/usr/share/roundcubemail"

# --- Utility Functions ---
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; }

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root (sudo)."
    exit 1
  fi
}

trap 'error "An unexpected error occurred on line $LINENO. Check logs or rollback."' ERR

ask_yes_no() {
  local question="$1" response
  while true; do
    read -r -p "$(echo -e "${CYAN}[?]${RESET} $question (y/n): ")" response
    case "$response" in
      [Yy]*) return 0 ;; [Nn]*) return 1 ;; *) warn "Please answer y or n." ;;
    esac
  done
}

# --- Clean Old Configurations ---
clean_old_configs() {
  info "${MAGENTA}=== CLEANING OLD MAIL HARDENER CONFIGURATIONS ===${RESET}"
  warn "This will remove all Mail Hardener configurations and reset to defaults."
  ask_yes_no "Continue with cleanup?" || { info "Cleanup cancelled."; exit 0; }
  
  info "Stopping mail services..."
  systemctl stop dovecot postfix httpd 2>/dev/null || true
  
  info "Cleaning Dovecot configurations..."
  for conf in /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/local.conf; do
    if [[ -f "$conf" ]]; then
      sed -i '/# === Mail Hardener/,/^$/d' "$conf" 2>/dev/null || true
    fi
  done
  if [[ -f /etc/dovecot/local.conf ]] && [[ ! -s /etc/dovecot/local.conf ]]; then
    rm -f /etc/dovecot/local.conf || true
  fi
  rm -f /etc/dovecot/conf.d/*.hardening-backup 2>/dev/null || true
  rm -f /etc/dovecot/local.conf.hardening-backup 2>/dev/null || true
  ok "Dovecot configurations cleaned."
  
  info "Cleaning Postfix configurations..."
  if [[ -f /etc/postfix/main.cf ]]; then
    sed -i '/# === Mail Hardener/,/^$/d' /etc/postfix/main.cf 2>/dev/null || true
  fi
  if [[ -f /etc/postfix/master.cf ]]; then
    sed -i '/# === Mail Hardener/,/^$/d' /etc/postfix/master.cf 2>/dev/null || true
    sed -i '/^submission inet.*smtpd$/,/^$/d' /etc/postfix/master.cf 2>/dev/null || true
  fi
  ok "Postfix configurations cleaned."
  
  info "Cleaning Roundcube configurations..."
  if [[ -f "$ROUNDCUBE_CONFIG" ]]; then
    sed -i '/\/\/ === Mail Hardener/,/^$/d' "$ROUNDCUBE_CONFIG" 2>/dev/null || true
    rm -f "${ROUNDCUBE_CONFIG}.hardening-backup" 2>/dev/null || true
  fi
  if [[ -d "$ROUNDCUBE_DIR/installer" ]]; then
    chmod 755 "$ROUNDCUBE_DIR/installer" 2>/dev/null || true
  fi
  if [[ -f /etc/httpd/conf.d/roundcubemail.conf ]]; then
    sed -i '/# Security Headers/,/Header set Referrer-Policy/d' /etc/httpd/conf.d/roundcubemail.conf 2>/dev/null || true
  fi
  ok "Roundcube configurations cleaned."
  
  if ask_yes_no "Reinstall packages to completely reset configurations?"; then
    info "Reinstalling Dovecot..."
    dnf reinstall -y dovecot 2>&1 || warn "Failed to reinstall Dovecot"
    info "Reinstalling Postfix..."
    dnf reinstall -y postfix 2>&1 || warn "Failed to reinstall Postfix"
  fi
  
  info "Restarting services..."
  for svc in "${SERVICES[@]}"; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      systemctl start "$svc" 2>/dev/null || warn "Failed to start $svc"
      if systemctl is-active --quiet "$svc"; then
        ok "$svc restarted successfully."
      else
        warn "$svc failed to start."
      fi
    fi
  done
  ok "${GREEN}Cleanup complete!${RESET}"
}

# --- Backup Configurations ---
backup_configs() {
  mkdir -p "$BACKUP_DIR"
  info "Creating backup at $BACKUP_FILE..."
  local backup_paths=("/etc/postfix" "/etc/dovecot")
  if [[ -d "/etc/roundcubemail" ]]; then
    backup_paths+=("/etc/roundcubemail")
  fi
  if [[ -f "/etc/httpd/conf.d/roundcubemail.conf" ]]; then
    backup_paths+=("/etc/httpd/conf.d/roundcubemail.conf")
  fi
  if tar -czpf "$BACKUP_FILE" "${backup_paths[@]}" 2>/dev/null; then
    ok "Backup complete."
  else
    error "Backup failed."
    exit 1
  fi
}

# --- Rollback ---
rollback_latest() {
  local latest
  latest="$(find "$BACKUP_DIR" -name "mail_backup_*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
  if [[ -z "$latest" ]]; then
    error "No backups found in $BACKUP_DIR."
    exit 1
  fi
  warn "This will restore configurations from: $latest"
  if ! ask_yes_no "Continue with rollback?"; then
    info "Rollback cancelled."
    exit 0
  fi
  info "Restoring from $latest..."
  if tar -xzpf "$latest" -C /; then
    for svc in "${SERVICES[@]}"; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        if systemctl restart "$svc"; then
          ok "Restarted $svc"
        else
          warn "Failed to restart $svc"
        fi
      fi
    done
    ok "Rollback complete."
  else
    error "Rollback failed."
    exit 1
  fi
}

# --- Generate SSL Certificates ---
generate_selfsigned_certs() {
  info "Generating self-signed SSL certificates..."
  local cert_file="/etc/pki/tls/certs/mail-selfsigned.crt" key_file="/etc/pki/tls/private/mail-selfsigned.key"
  [[ -f "$cert_file" ]] && [[ -f "$key_file" ]] && { warn "Self-signed certificates already exist. Skipping."; return 0; }
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$key_file" -out "$cert_file" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=mail.example.com" 2>/dev/null || { error "Failed to generate certificates."; return 1; }
  chmod 600 "$key_file"; chmod 644 "$cert_file"
  ok "Self-signed certificates generated: $cert_file"
}

# --- Configure Dovecot for Fedora ---
configure_dovecot_fedora() {
  info "Configuring Dovecot for Fedora compatibility..."
  local dovecot_local="/etc/dovecot/local.conf"
  [[ ! -f "$dovecot_local" ]] && { touch "$dovecot_local"; ok "Created $dovecot_local"; }
  grep -q "^protocols" /etc/dovecot/dovecot.conf "$dovecot_local" 2>/dev/null || echo "protocols = imap pop3 lmtp" >> "$dovecot_local"
  grep -q "^mail_location" /etc/dovecot/dovecot.conf "$dovecot_local" 2>/dev/null || echo "mail_location = maildir:~/Maildir" >> "$dovecot_local"
}

# --- Testing Mode: Install Services ---
install_services() {
  info "${MAGENTA}=== TESTING MODE: Installing Services ===${RESET}"
  warn "This will install Postfix, Dovecot, Roundcube, Apache, and dependencies."
  ask_yes_no "Continue with installation?" || { info "Installation cancelled."; exit 0; }
  
  local setup_ssl=false
  ask_yes_no "Generate self-signed SSL certificates for testing?" && setup_ssl=true
  
  info "Updating system packages..."; dnf update -y -q || warn "Failed to update packages."
  info "Installing Postfix..."; dnf install -y postfix || { error "Failed to install Postfix."; exit 1; }
  info "Installing Dovecot..."; dnf install -y dovecot || { error "Failed to install Dovecot."; exit 1; }
  info "Installing Apache (httpd)..."; dnf install -y httpd || { error "Failed to install Apache."; exit 1; }
  info "Installing PHP and required modules..."
  dnf install -y php php-common php-json php-xml php-mbstring php-intl php-pdo php-mysqlnd || { error "Failed to install PHP."; exit 1; }
  info "Installing Roundcube..."; dnf install -y roundcubemail || { error "Failed to install Roundcube."; exit 1; }
  
  configure_dovecot_fedora
  [[ "$setup_ssl" == true ]] && generate_selfsigned_certs
  
  info "Configuring Roundcube with SQLite database..."
  mkdir -p /var/lib/roundcubemail/db; chown apache:apache /var/lib/roundcubemail/db; chmod 750 /var/lib/roundcubemail/db
  [[ -f "$ROUNDCUBE_DIR/SQL/sqlite.initial.sql" ]] && {
    sqlite3 /var/lib/roundcubemail/db/roundcube.db < "$ROUNDCUBE_DIR/SQL/sqlite.initial.sql" 2>/dev/null || warn "Database may already be initialized."
    chown apache:apache /var/lib/roundcubemail/db/roundcube.db; chmod 640 /var/lib/roundcubemail/db/roundcube.db
  }
  
  [[ -f "$ROUNDCUBE_CONFIG" ]] && {
    cp "$ROUNDCUBE_CONFIG" "${ROUNDCUBE_CONFIG}.bak"
    sed -i "s|^\$config\['db_dsnw'\].*|\$config['db_dsnw'] = 'sqlite:////var/lib/roundcubemail/db/roundcube.db?mode=0640';|" "$ROUNDCUBE_CONFIG" || true
    sed -i "s|^\$config\['default_host'\].*|\$config['default_host'] = 'localhost';|" "$ROUNDCUBE_CONFIG" || true
    sed -i "s|^\$config\['smtp_server'\].*|\$config['smtp_server'] = 'localhost';|" "$ROUNDCUBE_CONFIG" || true
    local des_key
    des_key=$(openssl rand -base64 24)
    sed -i "s|^\$config\['des_key'\].*|\$config['des_key'] = '$des_key';|" "$ROUNDCUBE_CONFIG" || true
  }
  
  info "Configuring SELinux contexts for Roundcube..."
  if command -v semanage &>/dev/null && command -v restorecon &>/dev/null; then
    semanage fcontext -a -t httpd_sys_content_t "$ROUNDCUBE_DIR(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/roundcubemail(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "$ROUNDCUBE_DIR/temp(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "$ROUNDCUBE_DIR/logs(/.*)?" 2>/dev/null || true
    restorecon -Rv "$ROUNDCUBE_DIR" /var/lib/roundcubemail 2>/dev/null || true
  fi
  
  info "Setting file permissions..."
  chown -R root:apache "$ROUNDCUBE_DIR"
  find "$ROUNDCUBE_DIR" -type f -exec chmod 640 {} \;
  find "$ROUNDCUBE_DIR" -type d -exec chmod 750 {} \;
  chown -R apache:apache "$ROUNDCUBE_DIR/temp" "$ROUNDCUBE_DIR/logs"
  chmod 770 "$ROUNDCUBE_DIR/temp" "$ROUNDCUBE_DIR/logs"
  
  info "Configuring Apache for Roundcube..."
  [[ ! -f /etc/httpd/conf.d/roundcubemail.conf ]] && cat > /etc/httpd/conf.d/roundcubemail.conf <<'APACHECONF'
Alias /roundcube /usr/share/roundcubemail
<Directory /usr/share/roundcubemail>
    Options +FollowSymLinks
    AllowOverride All
    Require all granted
    <IfModule mod_php.c>
        php_value upload_max_filesize 10M
        php_value post_max_size 10M
        php_value memory_limit 64M
        php_flag display_errors Off
        php_flag log_errors On
    </IfModule>
</Directory>
<Directory /usr/share/roundcubemail/config>
    Require all denied
</Directory>
<Directory /usr/share/roundcubemail/temp>
    Require all denied
</Directory>
<Directory /usr/share/roundcubemail/logs>
    Require all denied
</Directory>
APACHECONF
  
  info "Configuring firewall..."
  command -v firewall-cmd &>/dev/null && {
    for svc in http https smtp smtps imap imaps; do firewall-cmd --permanent --add-service=$svc 2>/dev/null || true; done
    firewall-cmd --reload 2>/dev/null || true
    ok "Firewall rules added."
  }
  
  info "Enabling and starting services..."
  for svc in "${SERVICES[@]}"; do
    systemctl enable "$svc" 2>/dev/null || warn "Failed to enable $svc"
    systemctl start "$svc" 2>/dev/null || warn "Failed to start $svc"
    systemctl is-active --quiet "$svc" && ok "$svc is running." || warn "$svc failed to start. Check: systemctl status $svc"
  done
  
  ok "${GREEN}Installation complete!${RESET}"
  info "You can access Roundcube at: ${CYAN}http://localhost/roundcube${RESET}"
  warn "Services are installed but NOT hardened. Run this script again without --test to apply hardening."
}

# --- Postfix Hardening ---
harden_postfix() {
  info "Hardening Postfix..."
  local apply_ssl=false; ask_yes_no "Apply SSL/TLS hardening to Postfix?" && apply_ssl=true
  local config_additions=""
  
  if [[ "$apply_ssl" == true ]]; then
    local cert_file="/etc/pki/tls/certs/mail-selfsigned.crt" key_file="/etc/pki/tls/private/mail-selfsigned.key"
    [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]] && { warn "SSL certificates not found. Generating..."; generate_selfsigned_certs; }
    config_additions+="
# === Mail Hardener: TLS/SSL Configuration ===
smtpd_tls_security_level = may
smtpd_tls_cert_file = $cert_file
smtpd_tls_key_file = $key_file
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4, 3DES
smtp_tls_security_level = may
smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
"
  fi
  
  config_additions+="
# === Mail Hardener: General Security ===
disable_vrfy_command = yes
smtpd_helo_required = yes
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_data_restrictions = reject_unauth_pipelining
"
  
  echo "$config_additions" >> /etc/postfix/main.cf || { error "Failed to update Postfix main.cf"; exit 1; }
  
  if [[ "$apply_ssl" == true ]] && ! grep -q "^submission inet" /etc/postfix/master.cf; then
    cat <<'MASTERCONF' >> /etc/postfix/master.cf

# === Mail Hardener: Hardened submission service ===
submission inet n - n - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
MASTERCONF
  fi
  
  systemctl restart postfix && ok "Postfix hardened and restarted." || { error "Failed to restart Postfix. Check: journalctl -xeu postfix"; exit 1; }
}

# --- Dovecot Hardening ---
harden_dovecot() {
  info "Hardening Dovecot (Fedora configuration)..."
  local apply_ssl=false; ask_yes_no "Apply SSL/TLS hardening to Dovecot?" && apply_ssl=true
  local dovecot_local="/etc/dovecot/local.conf"
  [[ ! -f "$dovecot_local" ]] && touch "$dovecot_local"
  cp "$dovecot_local" "${dovecot_local}.hardening-backup" 2>/dev/null || true
  
  if [[ "$apply_ssl" == true ]]; then
    local cert_file="/etc/pki/tls/certs/mail-selfsigned.crt" key_file="/etc/pki/tls/private/mail-selfsigned.key"
    [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]] && { warn "SSL certificates not found. Generating..."; generate_selfsigned_certs; }
    cat <<SSLCONF >> "$dovecot_local"

# === Mail Hardener: SSL/TLS Configuration ===
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
ssl_prefer_server_ciphers = yes
ssl_cert = <$cert_file
ssl_key = <$key_file
SSLCONF
  fi
  
  cat <<'AUTHCONF' >> "$dovecot_local"

# === Mail Hardener: Authentication Security ===
disable_plaintext_auth = yes
auth_mechanisms = plain login

# === Mail Hardener: General Security ===
mail_privileged_group = mail
AUTHCONF
  
  info "Testing Dovecot configuration..."
  if doveconf -n >/dev/null 2>&1; then
    ok "Dovecot configuration is valid."
  else
    error "Dovecot configuration has errors."; doveconf -n || true
    cp "${dovecot_local}.hardening-backup" "$dovecot_local" 2>/dev/null || true
    error "Configuration test failed. Backup restored."; exit 1
  fi
  
  systemctl restart dovecot && ok "Dovecot hardened and restarted." || {
    error "Failed to restart Dovecot. Check: journalctl -xeu dovecot"
    cp "${dovecot_local}.hardening-backup" "$dovecot_local" 2>/dev/null || true
    exit 1
  }
}

# --- Roundcube Hardening ---
harden_roundcube() {
  info "Hardening Roundcube..."
  [[ ! -f "$ROUNDCUBE_CONFIG" ]] && { warn "Roundcube config not found. Skipping."; return 0; }
  cp "$ROUNDCUBE_CONFIG" "${ROUNDCUBE_CONFIG}.hardening-backup"
  
  info "Disabling Roundcube installer..."
  [[ -d "$ROUNDCUBE_DIR/installer" ]] && chmod 000 "$ROUNDCUBE_DIR/installer" 2>/dev/null || warn "Could not disable installer"
  
  grep -q "Mail Hardener: Security Headers" "$ROUNDCUBE_CONFIG" || cat <<'PHPCONF' >> "$ROUNDCUBE_CONFIG"

// === Mail Hardener: Security Headers ===
$config['enable_installer'] = false;
$config['x_frame_options'] = 'sameorigin';
$config['password_charset'] = 'UTF-8';
$config['useragent'] = 'Roundcube Webmail';
$config['session_lifetime'] = 10;
$config['session_samesite'] = 'Strict';
$config['login_rate_limit'] = 3;
$config['ip_check'] = true;
PHPCONF
  
  if [[ -f /etc/httpd/conf.d/roundcubemail.conf ]] && ! grep -q "Header set X-Frame-Options" /etc/httpd/conf.d/roundcubemail.conf; then
    sed -i '/<Directory \/usr\/share\/roundcubemail>/a\    # Security Headers\n    Header set X-Frame-Options "SAMEORIGIN"\n    Header set X-Content-Type-Options "nosniff"\n    Header set X-XSS-Protection "1; mode=block"\n    Header set Referrer-Policy "no-referrer-when-downgrade"' /etc/httpd/conf.d/roundcubemail.conf
  fi
  
  info "Securing file permissions..."
  chown -R root:apache "$ROUNDCUBE_DIR"
  find "$ROUNDCUBE_DIR" -type f -exec chmod 640 {} \;
  find "$ROUNDCUBE_DIR" -type d -exec chmod 750 {} \;
  chown -R apache:apache "$ROUNDCUBE_DIR/temp" "$ROUNDCUBE_DIR/logs"
  chmod 770 "$ROUNDCUBE_DIR/temp" "$ROUNDCUBE_DIR/logs"
  [[ -d /var/lib/roundcubemail ]] && { chown -R apache:apache /var/lib/roundcubemail; chmod 750 /var/lib/roundcubemail; }
  
  info "Applying SELinux contexts..."
  if command -v semanage &>/dev/null && command -v restorecon &>/dev/null; then
    semanage fcontext -a -t httpd_sys_content_t "$ROUNDCUBE_DIR(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "$ROUNDCUBE_DIR/temp(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "$ROUNDCUBE_DIR/logs(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/roundcubemail(/.*)?" 2>/dev/null || true
    restorecon -Rv "$ROUNDCUBE_DIR" /var/lib/roundcubemail 2>/dev/null || true
    ok "SELinux contexts applied."
  fi
  
  systemctl restart httpd && ok "Roundcube hardened and Apache restarted." || { error "Failed to restart Apache. Check: journalctl -xeu httpd"; exit 1; }
}

# --- Main ---
require_root

case "${1:-}" in
  --rollback) rollback_latest ;;
  --test) install_services ;;
  --clean) clean_old_configs ;;
  *)
    info "${MAGENTA}=== Mail Hardener for Fedora ===${RESET}"
    info "This will harden Postfix, Dovecot, and Roundcube."
    warn "Ensure services are already installed and running."
    ask_yes_no "Continue with hardening?" || { info "Hardening cancelled."; exit 0; }
    backup_configs; harden_postfix; harden_dovecot; harden_roundcube
    ok "${GREEN}Hardening complete!${RESET}"
    info "Backup stored at: $BACKUP_FILE"
    info "Test your configuration:"
    info "  - Postfix: systemctl status postfix"
    info "  - Dovecot: systemctl status dovecot"
    info "  - Apache:  systemctl status httpd"
    info "  - Roundcube: http://localhost/roundcube"
    ;;
esac
