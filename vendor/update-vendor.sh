#!/bin/bash
# ==============================================================================
# Vendor Update Script — Downloads/updates all vendored dependencies
#
# Run this once with GitHub access to populate the vendor/ directory.
# During competition (offline), scripts fall back to these local copies.
#
# Usage: ./update-vendor.sh
# ==============================================================================

set -euo pipefail

VENDOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
err()  { echo "[ERROR] $*" >&2; }

# Clone a repo, strip .git, place in vendor/<name>/source/
vendor_clone() {
    local name="$1" repo="$2"
    local dest="$VENDOR_DIR/$name/source"
    log "Cloning $repo → $name/source/"
    rm -rf "$dest"
    mkdir -p "$dest"
    local tmp
    tmp=$(mktemp -d)
    if git clone --depth 1 "$repo" "$tmp/repo" 2>/dev/null; then
        rm -rf "$tmp/repo/.git"
        cp -a "$tmp/repo/." "$dest/"
        rm -rf "$tmp"
        log "  OK"
    else
        rm -rf "$tmp"
        err "  Failed to clone $repo"
        return 1
    fi
}

# Download a single file
vendor_download() {
    local name="$1" url="$2" filename="$3"
    local dest="$VENDOR_DIR/$name"
    mkdir -p "$dest"
    log "Downloading $url → $name/$filename"
    if curl -fsSL "$url" -o "$dest/$filename"; then
        log "  OK ($(du -h "$dest/$filename" | cut -f1))"
    else
        err "  Failed to download $url"
        return 1
    fi
}

failed=0

# ── Binaries ──────────────────────────────────────────────────────────────

# AVML — memory acquisition tool
vendor_download "avml" \
    "https://github.com/microsoft/avml/releases/latest/download/avml" \
    "avml" || ((failed++))
chmod +x "$VENDOR_DIR/avml/avml" 2>/dev/null || true

# Coraza SPOA — no pre-built binary available; vendor source only.
# The existing vendor/coraza-spoa/source/ is used for building from source.
# Remove the broken placeholder binary if present.
if [[ -f "$VENDOR_DIR/coraza-spoa/coraza-spoa_Linux_x86_64.tar.gz" ]] && \
   [[ $(stat -c%s "$VENDOR_DIR/coraza-spoa/coraza-spoa_Linux_x86_64.tar.gz") -lt 100 ]]; then
    log "Removing broken coraza-spoa binary placeholder"
    rm -f "$VENDOR_DIR/coraza-spoa/coraza-spoa_Linux_x86_64.tar.gz"
fi

# dwarf2json — Volatility symbol generation
vendor_download "dwarf2json" \
    "https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-amd64" \
    "dwarf2json-linux-amd64" || ((failed++))
chmod +x "$VENDOR_DIR/dwarf2json/dwarf2json-linux-amd64" 2>/dev/null || true

# LinPEAS — privilege escalation scanner
vendor_download "linpeas" \
    "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
    "linpeas.sh" || ((failed++))

# SoftEther VPN Server
vendor_download "softether" \
    "https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.44-9807-rtm/softether-vpnserver-v4.44-9807-rtm-2025.04.16-linux-x64-64bit.tar.gz" \
    "softether-vpnserver-v4.44-9807-rtm-2025.04.16-linux-x64-64bit.tar.gz" || ((failed++))

# Sysmon config (SwiftOnSecurity)
vendor_download "sysmon-config" \
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" \
    "sysmonconfig-export.xml" || ((failed++))

# Wazuh Elasticsearch template (match deployed version)
vendor_download "wazuh-template" \
    "https://raw.githubusercontent.com/wazuh/wazuh/v4.14.2/extensions/elasticsearch/7.x/wazuh-template.json" \
    "wazuh-template.json" || ((failed++))

# ── Git Repos (cloned, .git stripped) ─────────────────────────────────────

# Cowrie SSH/Telnet honeypot
vendor_clone "cowrie" "https://github.com/cowrie/cowrie.git" || ((failed++))

# Endlessh SSH tarpit
vendor_clone "endlessh" "https://github.com/skeeto/endlessh.git" || ((failed++))

# SOCFortress Wazuh rules
vendor_clone "socfortress-wazuh-rules" "https://github.com/socfortress/Wazuh-Rules.git" || ((failed++))

# UAC — Unix-like Artifacts Collector
vendor_clone "uac" "https://github.com/tclahr/uac.git" || ((failed++))

# YARA rules (neo23x0/signature-base)
vendor_clone "yara-rules" "https://github.com/neo23x0/signature-base.git" || ((failed++))

# ── Skipped (version-pinned, keep as-is) ──────────────────────────────────
# vendor/opencart/opencart-4.0.2.3.zip          — keep existing
# vendor/owasp-crs/coreruleset-v4.0.0.tar.gz    — keep existing
# vendor/coraza-spoa/source/                     — keep existing source build

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "========================================="
if [[ "$failed" -eq 0 ]]; then
    log "All vendors updated successfully!"
else
    warn "$failed vendor(s) failed to update — check output above"
fi
echo "========================================="

# Verify critical files aren't broken placeholders
echo ""
log "Verification:"
for f in \
    "avml/avml" \
    "cowrie/source/setup.py" \
    "dwarf2json/dwarf2json-linux-amd64" \
    "endlessh/source/endlessh.c" \
    "linpeas/linpeas.sh" \
    "softether/softether-vpnserver-v4.44-9807-rtm-2025.04.16-linux-x64-64bit.tar.gz" \
    "socfortress-wazuh-rules/source/README.md" \
    "sysmon-config/sysmonconfig-export.xml" \
    "uac/source/uac" \
    "wazuh-template/wazuh-template.json" \
    "yara-rules/source/README.md"; do
    path="$VENDOR_DIR/$f"
    if [[ -f "$path" ]] && [[ $(stat -c%s "$path" 2>/dev/null || echo 0) -gt 100 ]]; then
        echo "  OK  $f ($(du -h "$path" | cut -f1))"
    else
        echo "  FAIL $f (missing or too small)"
        ((failed++))
    fi
done

exit "$failed"
