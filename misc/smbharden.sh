#!/usr/bin/env bash
# harden_samba_competition.sh
#
# Competition-safe Samba hardening for Ubuntu (Cowbuntu SMB server).
# - Preserves service availability (minimize scoring outages)
# - Restricts SMB to internal network
# - Disables SMB1 + weak auth fallbacks
# - Disables guest/anonymous
# - Enables signing; encryption optional (toggle)
# - Adds basic logging + fail2ban
# - Adds UFW rules (if UFW present)
#
# Optional env overrides:
#   ALLOW_SUBNET="192.168.1.0/24" ENCRYPT_MODE="desired" sudo -E bash harden_samba_competition.sh
#
set -euo pipefail

# -----------------------------
# User-tunable settings
# -----------------------------
ALLOW_SUBNET="${ALLOW_SUBNET:-192.168.1.0/24}"   # competition internal subnet
ENCRYPT_MODE="${ENCRYPT_MODE:-desired}"          # desired|required|off
SMB_MIN="${SMB_MIN:-SMB2}"
SMB_MAX="${SMB_MAX:-SMB3}"
CONF="/etc/samba/smb.conf"
STAMP="$(date +%F_%H%M%S)"
BACKUP="/root/smb.conf.${STAMP}.bak"
DROPIN_DIR="/etc/samba/smb.conf.d"
DROPIN_FILE="${DROPIN_DIR}/99-hardening.conf"

# -----------------------------
# Helpers
# -----------------------------
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
die() { echo -e "[x] $*" >&2; exit 1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Safely ensure a setting exists inside a given ini section in a file.
# We intentionally write hardening settings into a drop-in file to avoid mangling smb.conf.
write_dropin() {
  mkdir -p "${DROPIN_DIR}"
  cat > "${DROPIN_FILE}" <<EOF
# Auto-generated hardening (competition-safe): ${STAMP}
# This file is included from smb.conf (we add include = ... once).
# Remove this file and restart smbd to revert hardening quickly.
[global]
  # ---- Protocol hardening ----
  server min protocol = ${SMB_MIN}
  server max protocol = ${SMB_MAX}
  # ---- Authentication hardening ----
  lanman auth = no
  ntlm auth = no
  client lanman auth = no
  client ntlmv2 auth = yes
  # ---- Guest / anonymous hardening ----
  map to guest = never
  restrict anonymous = 2
  usershare allow guests = no
  # ---- MITM protections ----
  server signing = mandatory
  # ---- Encryption toggle ----
  smb encrypt = ${ENCRYPT_MODE}
  # ---- Safer defaults ----
  unix extensions = no
  disable spoolss = yes
  # ---- Logging ----
  log level = 1 auth:3
  logging = file
  max log size = 1000
  # ---- Network allow/deny (extra layer beyond firewall) ----
  hosts allow = ${ALLOW_SUBNET}
  hosts deny  = 0.0.0.0/0
EOF
}

ensure_include_dropin() {
  # If smb.conf already includes smb.conf.d, don't duplicate.
  if grep -qiE '^\s*include\s*=\s*/etc/samba/smb\.conf\.d/\*\.conf' "${CONF}"; then
    log "smb.conf already includes ${DROPIN_DIR}/*.conf"
    return 0
  fi

  # Back up once, then append include at end (lowest risk change).
  if [[ ! -f "${BACKUP}" ]]; then
    cp -a "${CONF}" "${BACKUP}"
    log "Backed up ${CONF} -> ${BACKUP}"
  fi

  echo "" >> "${CONF}"
  echo "# Include drop-in configs (competition hardening)" >> "${CONF}"
  echo "include = ${DROPIN_DIR}/*.conf" >> "${CONF}"
  log "Added include directive to smb.conf"
}

install_packages() {
  log "Installing required packages (samba, smbclient, ufw, fail2ban)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y samba smbclient ufw fail2ban
}

validate_config() {
  log "Validating Samba configuration with testparm..."
  testparm -s >/dev/null
}

restart_services() {
  log "Restarting Samba services..."
  systemctl restart smbd || die "Failed to restart smbd"
  systemctl restart nmbd || warn "nmbd restart failed (may be disabled on your setup)"
  systemctl enable smbd >/dev/null 2>&1 || true
  systemctl enable nmbd >/dev/null 2>&1 || true
}

configure_ufw() {
  if ! have_cmd ufw; then
    warn "UFW not installed; skipping firewall step."
    return 0
  fi

  log "Configuring UFW to allow SMB only from ${ALLOW_SUBNET}..."
  # Allow from internal subnet
  ufw allow from "${ALLOW_SUBNET}" to any port 445 proto tcp >/dev/null
  ufw allow from "${ALLOW_SUBNET}" to any port 139 proto tcp >/dev/null

  # Deny everyone else (explicit)
  ufw deny 445/tcp >/dev/null || true
  ufw deny 139/tcp >/dev/null || true

  # Enable if inactive (safe promptless enable)
  if ufw status | grep -qi "Status: inactive"; then
    ufw --force enable >/dev/null
  fi

  log "UFW status:"
  ufw status verbose || true
}

configure_fail2ban() {
  if ! have_cmd fail2ban-client; then
    warn "fail2ban not installed; skipping brute-force protection."
    return 0
  fi

  log "Configuring fail2ban for Samba auth failures..."
  # Create a minimal jail override for Samba.
  # On Ubuntu, Samba auth failures typically appear in /var/log/samba/log.* and sometimes syslog.
  cat > /etc/fail2ban/jail.d/samba.conf <<'EOF'
[samba]
enabled = true
port    = 445,139
filter  = samba
logpath = /var/log/samba/log.*
maxretry = 5
findtime = 10m
bantime  = 1h
EOF

  systemctl restart fail2ban
  log "fail2ban samba jail status (if available):"
  fail2ban-client status samba || true
}

quick_smoke_test() {
  log "Quick smoke test: list shares as current user context (may prompt for password if run without -N)..."
  # We avoid passing passwords in scripts. This checks service responsiveness, not auth.
  smbclient -L localhost -N >/dev/null 2>&1 && \
    log "Anonymous share listing worked (may be limited) - service responds." || \
    log "Anonymous listing blocked or requires auth (fine) - service still needs authenticated test."
}

show_next_manual_tests() {
  cat <<EOF
============================================================
NEXT MANUAL VERIFICATION (DO THESE RIGHT NOW)
============================================================
1) Confirm Samba is listening:
   ss -tulnp | egrep '(:445|:139)'
2) Confirm config is clean:
   testparm -s
3) Confirm your real share still works (authenticated):
   smbclient -L localhost -U <your_user>
   smbclient //localhost/<YourShare> -U <your_user>
4) If Windows is in scope:
   On a Windows host: \\\\$(hostname -I | awk '{print $1}')\\<YourShare>
Notes:
- We intentionally did NOT change user passwords (policy + scoring safety).
- If ENCRYPT_MODE=required breaks a legacy client, re-run with:
    ENCRYPT_MODE=desired sudo -E bash harden_samba_competition.sh
============================================================
EOF
}

# -----------------------------
# Main
# -----------------------------
need_root

log "Starting competition-safe Samba hardening..."
log "Allow subnet: ${ALLOW_SUBNET}"
log "Encryption mode: ${ENCRYPT_MODE} (recommended: desired first, then required if clients support it)"

install_packages

# Drop-in hardening config + include line
write_dropin
ensure_include_dropin

# Validate before restarting (prevents scoring outage from bad config)
validate_config
restart_services

# Firewall + brute-force protection
configure_ufw
configure_fail2ban

# Final validation
validate_config
quick_smoke_test

log "Hardening applied successfully."
log "Backup saved at: ${BACKUP}"
log "Hardening drop-in: ${DROPIN_FILE}"

show_next_manual_tests
