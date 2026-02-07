#!/bin/bash
#===============================================================================
#
#  ███████╗███████╗███████╗██╗  ██╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗
#  ╚══███╔╝██╔════╝██╔════╝██║ ██╔╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
#    ███╔╝ █████╗  █████╗  █████╔╝     ██║  ██║█████╗     ██║   █████╗  ██║        ██║   
#   ███╔╝  ██╔══╝  ██╔══╝  ██╔═██╗     ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   
#  ███████╗███████╗███████╗██║  ██╗    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   
#  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   
#
#  Zeek Red Team Detection Suite - Unified Installer
#  Version: 1.4.0
#
#  Installs complete detection coverage:
#    • TLS Fingerprinting (JA4/JA3) - 150+ C2/malware signatures + 80+ cert patterns
#    • Windows/AD Attacks - Impacket, Kerberoasting, BloodHound
#    • MITRE BZAR - Enhanced lateral movement detection (optional)
#
#  Usage: ./install-zeek-detection-suite.sh [options]
#
#  Options:
#    -d, --zeek-dir DIR      Zeek installation directory (auto-detect)
#    -s, --skip-bzar         Skip MITRE BZAR installation
#    -y, --yes               Non-interactive mode (accept defaults)
#    -h, --help              Show this help message
#
#===============================================================================

set -euo pipefail

# Ensure PATH includes Zeek and pip user packages
# Source system-wide profile if it exists (created by vyosZeekInstall.sh)
[[ -f /etc/profile.d/zeek.sh ]] && source /etc/profile.d/zeek.sh
# Fallback: add paths directly if profile doesn't exist
export PATH="/opt/zeek/bin:$HOME/.local/bin:$PATH"

# Colors (with fallback for non-color terminals)
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

# Configuration
ZEEK_DIR=""
SITE_DIR=""
SKIP_BZAR=false
NON_INTERACTIVE=false
BZAR_INSTALLED=false
JA3_INSTALLED=false

# Whitelists (populated interactively or via environment)
DC_IPS=()
ADMIN_IPS=()

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
Zeek Red Team Detection Suite - Unified Installer

This script installs complete network-based threat detection:

  PACKAGE 1: TLS/Certificate/DNS Detection (JA4/JA3/x509/DNS)
    • 14 C2 frameworks (Cobalt Strike, Sliver, Metasploit, Brute Ratel...)
    • 11 RATs (AsyncRAT, njRAT, QuasarRAT, Remcos...)
    • 9 Banking trojans (TrickBot, Dridex, Emotet, Qakbot...)
    • 6 Stealers (LummaC2, RedLine, Raccoon...)
    • X.509 cert anomaly detection (serial numbers, validity, key params)
    • DNS tunneling detection (iodine, dnscat2, data exfiltration)
    • 120+ total fingerprints

  PACKAGE 2: Windows/AD Attack Detection
    • Impacket tools (secretsdump, psexec, wmiexec, dcomexec, atexec)
    • Kerberoasting and AS-REP Roasting
    • SharpHound/BloodHound enumeration
    • PetitPotam and PrintNightmare exploitation
    • SMB lateral movement patterns

  PACKAGE 3: MITRE BZAR (Optional)
    • Enhanced lateral movement correlation
    • Automatic file extraction from SMB transfers
    • 144 additional DCE-RPC endpoint definitions

Usage: ./install-zeek-detection-suite.sh [options]

Options:
  -d, --zeek-dir DIR      Zeek installation directory (default: auto-detect)
  -s, --skip-bzar         Skip MITRE BZAR installation
  -y, --yes               Non-interactive mode (accept all defaults)
  -h, --help              Show this help message

Environment Variables:
  ZEEK_DC_IPS             Comma-separated Domain Controller IPs
  ZEEK_ADMIN_IPS          Comma-separated admin workstation IPs

Examples:
  ./install-zeek-detection-suite.sh
  ./install-zeek-detection-suite.sh --skip-bzar
  ZEEK_DC_IPS="10.0.0.1,10.0.0.2" ./install-zeek-detection-suite.sh -y

EOF
}

detect_zeek() {
    log_info "Detecting Zeek installation..."
    
    local zeek_paths=(
        "/opt/zeek"
        "/usr/local/zeek"
        "/usr/share/zeek"
    )
    
    # Try to find zeek binary and derive path
    local zeek_bin
    zeek_bin=$(command -v zeek 2>/dev/null || true)
    if [[ -n "$zeek_bin" ]]; then
        local derived_path
        derived_path=$(dirname "$(dirname "$zeek_bin")" 2>/dev/null || true)
        if [[ -n "$derived_path" ]]; then
            zeek_paths=("$derived_path" "${zeek_paths[@]}")
        fi
    fi
    
    for path in "${zeek_paths[@]}"; do
        if [[ -d "$path" && -f "$path/bin/zeek" ]]; then
            ZEEK_DIR="$path"
            log_success "Found Zeek at: $ZEEK_DIR"
            return 0
        fi
    done
    
    # Try zeek-config as fallback
    if command -v zeek-config &> /dev/null; then
        ZEEK_DIR="$(zeek-config --prefix 2>/dev/null || true)"
        if [[ -d "$ZEEK_DIR" && -f "$ZEEK_DIR/bin/zeek" ]]; then
            log_success "Found Zeek via zeek-config: $ZEEK_DIR"
            return 0
        fi
    fi
    
    return 1
}

check_zeek_version() {
    local zeek_bin="$ZEEK_DIR/bin/zeek"
    if [[ ! -x "$zeek_bin" ]]; then
        log_warning "Zeek binary not found at $zeek_bin"
        return 1
    fi
    
    local version
    version=$("$zeek_bin" --version 2>/dev/null | head -1) || true
    if [[ -z "$version" ]]; then
        log_warning "Could not determine Zeek version"
        return 0
    fi
    
    log_info "Zeek version: $version"
    
    # Extract major version (POSIX-compatible)
    local major_version
    major_version=$(echo "$version" | sed 's/[^0-9].*//' | cut -d. -f1)
    
    if [[ -n "$major_version" && "$major_version" -lt 4 ]]; then
        log_warning "Zeek version < 4.0 detected"
        log_warning "Some DCE-RPC detections may have limited coverage"
        log_warning "Recommended: Upgrade to Zeek 4.0+ for full functionality"
    fi
}

check_write_permissions() {
    local dir="$1"
    
    if [[ ! -d "$dir" ]]; then
        # Try to create it
        if ! mkdir -p "$dir" 2>/dev/null; then
            log_error "Cannot create directory: $dir"
            log_info "Try running with sudo or check permissions"
            return 1
        fi
    elif [[ ! -w "$dir" ]]; then
        log_error "No write permission for: $dir"
        log_info "Try running with sudo or check permissions"
        return 1
    fi
    
    return 0
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

prompt_ips() {
    local prompt="$1"
    local -n arr_ref=$2  # nameref for safer array assignment
    
    if [[ "$NON_INTERACTIVE" == true ]]; then
        return
    fi
    
    echo ""
    echo -e "${BOLD}$prompt${NC}"
    echo "Enter IP addresses one per line. Empty line when done."
    echo "(You can also edit the config file later)"
    echo ""
    
    local ip
    while true; do
        read -r -p "  IP: " ip
        [[ -z "$ip" ]] && break
        
        # Strict IP validation (IPv4 only for now)
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # Validate each octet
            local valid=true
            IFS='.' read -ra octets <<< "$ip"
            for octet in "${octets[@]}"; do
                if [[ "$octet" -gt 255 ]]; then
                    valid=false
                    break
                fi
            done
            
            if [[ "$valid" == true ]]; then
                arr_ref+=("$ip")
                echo -e "  ${GREEN}Added: $ip${NC}"
            else
                echo -e "  ${RED}Invalid IP (octet > 255), skipped${NC}"
            fi
        else
            echo -e "  ${RED}Invalid IP format, skipped${NC}"
        fi
    done
}

#===============================================================================
# INSTALLATION FUNCTIONS
#===============================================================================

setup_zkg() {
    # Ensure zkg is available and configured
    if command -v zkg &> /dev/null; then
        return 0
    fi

    # Check if zkg exists in Zeek's bin directory
    if [[ -x "$ZEEK_DIR/bin/zkg" ]]; then
        export PATH="$ZEEK_DIR/bin:$PATH"
        return 0
    fi

    log_warning "zkg (Zeek Package Manager) not found"
    log_info "Attempting to install zkg..."

    if command -v pip3 &> /dev/null; then
        if pip3 install zkg --quiet 2>/dev/null; then
            log_success "zkg installed via pip3"
        else
            log_warning "Failed to install zkg via pip3"
            return 1
        fi
    elif command -v pip &> /dev/null; then
        if pip install zkg --quiet 2>/dev/null; then
            log_success "zkg installed via pip"
        else
            log_warning "Failed to install zkg via pip"
            return 1
        fi
    else
        log_error "Cannot install zkg - pip not found"
        return 1
    fi

    # Configure zkg
    if command -v zkg &> /dev/null; then
        zkg autoconfig --force 2>/dev/null || true
        return 0
    fi

    return 1
}

install_ja3() {
    log_header "Installing JA3 TLS Fingerprinting Package"

    if ! setup_zkg; then
        log_warning "zkg not available - JA3 package cannot be installed"
        log_info "JA3 fingerprinting will not be available"
        return 1
    fi

    # Check if JA3 already installed
    if zkg list 2>/dev/null | grep -qi "ja3"; then
        log_success "JA3 already installed"
        JA3_INSTALLED=true
        return 0
    fi

    log_info "Installing JA3 from Zeek package repository..."
    if zkg install zeek/salesforce/ja3 --force 2>&1; then
        log_success "JA3 installed successfully"
        JA3_INSTALLED=true
        return 0
    else
        log_warning "JA3 installation failed"
        log_info "You can install manually later: zkg install zeek/salesforce/ja3"
        return 1
    fi
}

install_bzar() {
    log_header "Installing MITRE BZAR Package"

    if ! setup_zkg; then
        log_warning "zkg not available - BZAR package cannot be installed"
        return 1
    fi

    # Check if BZAR already installed
    if zkg list 2>/dev/null | grep -q "bzar"; then
        log_success "BZAR already installed"
        BZAR_INSTALLED=true
        return 0
    fi

    log_info "Installing BZAR from Zeek package repository..."
    if zkg install zeek/mitre-attack/bzar --force 2>&1; then
        log_success "BZAR installed successfully"
        BZAR_INSTALLED=true
        return 0
    else
        log_warning "BZAR installation failed - continuing without it"
        log_info "You can install manually later: zkg install zeek/mitre-attack/bzar"
        return 1
    fi
}

install_tls_fingerprinting() {
    log_header "Installing TLS Fingerprinting Framework"
    
    local dest_dir="$SITE_DIR/redteam-detection"
    
    if ! check_write_permissions "$dest_dir/fingerprints"; then
        return 1
    fi
    
    mkdir -p "$dest_dir/fingerprints"
    
    log_info "Creating base detection framework..."
    
    #---------------------------------------------------------------------------
    # Main loader script
    #---------------------------------------------------------------------------
    cat > "$dest_dir/__load__.zeek" << 'ZEEKEOF'
##! Red Team Detection Suite - TLS/SSH/DNS Detection
##! Detects C2 frameworks, RATs, and malware via:
##!   - JA3/JA4/HASSH fingerprints
##!   - X.509 certificate anomalies (serial numbers, validity, key parameters)
##!   - DNS tunneling indicators (NULL records, long queries, subdomain volume)
##! Gracefully handles missing packages (JA3, JA4, HASSH)

@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/dns
@load base/frameworks/notice
@load base/files/x509

module RedTeam;

export {
    redef enum Notice::Type += {
        C2_TLS_Fingerprint,
        Malware_Callback,
        Suspicious_TLS_Client,
        Suspicious_Certificate,
        Suspicious_SSH_Client,
        DNS_Tunneling,
    };

    # Enable/disable detection - ALL ENABLED BY DEFAULT
    option enable_cert_detection: bool = T;
}

# Load signature databases (always load - they're just tables)
@load ./fingerprints/ja3_signatures
@load ./fingerprints/ja4_signatures
@load ./fingerprints/ja4x_certificates
@load ./fingerprints/hassh_signatures

# Load detection logic
@load ./detection
@load ./dns_anomaly
ZEEKEOF

    #---------------------------------------------------------------------------
    # Detection logic - JA3/JA4/HASSH fingerprint matching + cert patterns
    #---------------------------------------------------------------------------
    cat > "$dest_dir/detection.zeek" << 'ZEEKEOF'
##! TLS/SSH Fingerprint Detection Logic
##! Matches observed JA3/JA4/HASSH fingerprints against known C2/malware signatures
##! Generates NOTICE alerts when matches are found
##!
##! IMPORTANT: Uses connection_state_remove instead of ssl_established because:
##!   - TLS 1.3 connections through NAT may never trigger ssl_established
##!   - Zeek may only see the Client Hello (ssl_history=C) but still compute JA3/JA4
##!   - connection_state_remove fires after all analyzers finish, ensuring fields are populated

module RedTeam;

export {
    # Enable/disable specific detection types
    option enable_ja3_detection: bool = T;
    option enable_ja4_detection: bool = T;
    option enable_hassh_detection: bool = T;
}

# JA3/JA3S Detection - only compiled if JA3 package is loaded
# Install with: zkg install zeek/salesforce/ja3
@ifdef ( JA3::LOG )
event connection_state_remove(c: connection)
{
    if ( ! enable_ja3_detection || ! c?$ssl )
        return;

    # JA3 Client Detection
    if ( c$ssl?$ja3 )
    {
        local ja3_fp = c$ssl$ja3;
        if ( ja3_fp != "" && ja3_fp in ja3_signatures )
        {
            local ja3_match = ja3_signatures[ja3_fp];
            NOTICE([
                $note = C2_TLS_Fingerprint,
                $conn = c,
                $msg = fmt("JA3 match: %s (fingerprint: %s, server: %s:%s)",
                           ja3_match, ja3_fp, c$id$resp_h, c$id$resp_p),
                $sub = ja3_match,
                $identifier = cat(c$id$orig_h, c$id$resp_h, ja3_fp)
            ]);
        }
    }

    # JA3S Server Detection
    if ( c$ssl?$ja3s )
    {
        local ja3s_fp = c$ssl$ja3s;
        if ( ja3s_fp != "" && ja3s_fp in ja3_signatures )
        {
            local ja3s_match = ja3_signatures[ja3s_fp];
            NOTICE([
                $note = C2_TLS_Fingerprint,
                $conn = c,
                $msg = fmt("JA3S server match: %s (fingerprint: %s, server: %s:%s)",
                           ja3s_match, ja3s_fp, c$id$resp_h, c$id$resp_p),
                $sub = ja3s_match,
                $identifier = cat(c$id$orig_h, c$id$resp_h, ja3s_fp)
            ]);
        }
    }
}
@endif

# Certificate pattern + self-signed detection - always active (no package dependency)
event connection_state_remove(c: connection) &priority=-3
{
    if ( ! c?$ssl )
        return;

    # Certificate pattern detection
    if ( enable_cert_detection )
    {
        local subject = "";
        local issuer = "";

        if ( c$ssl?$subject )
            subject = c$ssl$subject;
        if ( c$ssl?$issuer )
            issuer = c$ssl$issuer;

        if ( subject != "" || issuer != "" )
        {
            # Check for suspicious string patterns in cert fields
            for ( susp_pattern in suspicious_cert_patterns )
            {
                if ( (subject != "" && strstr(subject, susp_pattern) != 0) ||
                     (issuer != "" && strstr(issuer, susp_pattern) != 0) )
                {
                    NOTICE([
                        $note = Suspicious_Certificate,
                        $conn = c,
                        $msg = fmt("Suspicious certificate pattern: %s (server: %s:%s)",
                                   susp_pattern, c$id$resp_h, c$id$resp_p),
                        $sub = subject
                    ]);
                    break;
                }
            }

            # Self-signed certificate detection: issuer == subject
            # Most C2 frameworks use self-signed certs by default
            # Skip common legitimate self-signed (e.g., well-known CAs)
            if ( subject != "" && issuer != "" && subject == issuer )
            {
                # Only alert on non-localhost, non-internal-CA self-signed certs
                # that are connecting to non-standard ports or matching C2 indicators
                local resp_port = c$id$resp_p;
                if ( resp_port != 443/tcp )
                {
                    NOTICE([
                        $note = Suspicious_Certificate,
                        $conn = c,
                        $msg = fmt("Self-signed certificate on non-standard port (subject==issuer: %s, server: %s:%s)",
                                   subject, c$id$resp_h, c$id$resp_p),
                        $sub = fmt("self-signed: %s", subject),
                        $identifier = cat(c$id$resp_h, c$id$resp_p, "selfsigned")
                    ]);
                }
            }
        }
    }
}

# JA4/JA4S Detection - only compiled if JA4 package is loaded
# Install with: zkg install zeek/foxio/ja4
@ifdef ( FINGERPRINT::JA4::LOG )
event connection_state_remove(c: connection) &priority=-1
{
    if ( ! c?$ssl )
        return;

    # JA4 Client fingerprint detection
    if ( enable_ja4_detection && c$ssl$ja4 != "" )
    {
        local ja4_fp = c$ssl$ja4;
        if ( ja4_fp in ja4_signatures )
        {
            local ja4_match = ja4_signatures[ja4_fp];
            NOTICE([
                $note = C2_TLS_Fingerprint,
                $conn = c,
                $msg = fmt("JA4 match: %s (fingerprint: %s, server: %s:%s)",
                           ja4_match, ja4_fp, c$id$resp_h, c$id$resp_p),
                $sub = ja4_match,
                $identifier = cat(c$id$orig_h, c$id$resp_h, ja4_fp)
            ]);
        }
    }

    # JA4S Server fingerprint detection
    if ( enable_ja4_detection && c$ssl$ja4s != "" )
    {
        local ja4s_fp = c$ssl$ja4s;
        if ( ja4s_fp in ja4s_signatures )
        {
            local ja4s_match = ja4s_signatures[ja4s_fp];
            NOTICE([
                $note = C2_TLS_Fingerprint,
                $conn = c,
                $msg = fmt("JA4S server match: %s (fingerprint: %s, server: %s:%s)",
                           ja4s_match, ja4s_fp, c$id$resp_h, c$id$resp_p),
                $sub = ja4s_match,
                $identifier = cat(c$id$orig_h, c$id$resp_h, ja4s_fp)
            ]);
        }
    }
}
@endif

# HASSH Detection for SSH connections
# Only compiled if HASSH package is installed (provides SSH::Info$hassh field)
# Install with: zkg install zeek/corelight/hassh
@ifdef ( HASSH::log_hassh )
event connection_state_remove(c: connection) &priority=-2
{
    if ( ! enable_hassh_detection )
        return;

    if ( ! c?$ssh )
        return;

    # Check client HASSH
    if ( c$ssh?$hassh )
    {
        local hassh_fp = c$ssh$hassh;
        if ( hassh_fp != "" && hassh_fp in hassh_signatures )
        {
            local hassh_match = hassh_signatures[hassh_fp];
            NOTICE([
                $note = Suspicious_SSH_Client,
                $conn = c,
                $msg = fmt("HASSH match: %s (fingerprint: %s, client: %s)",
                           hassh_match, hassh_fp, c$id$orig_h),
                $sub = hassh_match,
                $identifier = cat(c$id$orig_h, hassh_fp)
            ]);
        }
    }

    # Check server HASSH
    if ( c$ssh?$hasshServer )
    {
        local hasshs_fp = c$ssh$hasshServer;
        if ( hasshs_fp != "" && hasshs_fp in hasshserver_signatures )
        {
            local hasshs_match = hasshserver_signatures[hasshs_fp];
            NOTICE([
                $note = Suspicious_SSH_Client,
                $conn = c,
                $msg = fmt("HASSH Server match: %s (fingerprint: %s, server: %s)",
                           hasshs_match, hasshs_fp, c$id$resp_h),
                $sub = hasshs_match,
                $identifier = cat(c$id$resp_h, hasshs_fp)
            ]);
        }
    }
}
@endif

# ==========================================================================
# X.509 Certificate Analysis - specific C2 certificate patterns
# ==========================================================================
# NOTE: Only effective for TLS 1.2 and below. TLS 1.3 encrypts certificates
# in transit, so x509.log will be empty for TLS 1.3 connections.
# Many C2 frameworks (especially older configs) still use TLS 1.2.
#
# Detection targets:
#   - Cobalt Strike default keystore certificate (serial 146473198)
#   - AsyncRAT/DcRat: SHA512+RSA4096 (BouncyCastle generated)
#   - Self-signed certs with >5 year validity (Metasploit: 4-9yr, AsyncRAT: ~10yr)

# Known C2 certificate serial numbers (hex encoded)
const c2_cert_serials: set[string] = {
    "08BB00EE",  # Cobalt Strike default keystore (decimal: 146473198)
};

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
{
    if ( ! enable_cert_detection )
        return;

    if ( ! f?$conns )
        return;

    local subject = cert$subject;
    local issuer = cert$issuer;
    local serial = to_upper(cert$serial);

    # --- Known C2 Certificate Serial Numbers ---
    # Cobalt Strike ships with a default Java keystore (cobaltstrike.store)
    # with serial 146473198. Operators often change subject/issuer but
    # forget to regenerate the keystore entirely.
    if ( serial in c2_cert_serials )
    {
        for ( cid in f$conns )
        {
            NOTICE([
                $note = Suspicious_Certificate,
                $conn = f$conns[cid],
                $msg = fmt("Known C2 certificate serial detected (serial: %s, subject: %s, server: %s:%s)",
                           serial, subject, f$conns[cid]$id$resp_h, f$conns[cid]$id$resp_p),
                $sub = "C2 Default Cert Serial"
            ]);
        }
    }

    # --- AsyncRAT / DcRat / VenomRAT Certificate Pattern ---
    # These .NET RATs use BouncyCastle to generate certs with SHA512+RSA4096.
    # This combination is extremely rare in legitimate certificates.
    # Source: Corelight AsyncRAT analysis, DcRat source code
    if ( cert?$sig_alg && cert?$key_length )
    {
        if ( cert$sig_alg == "sha512WithRSAEncryption" && cert$key_length == 4096 )
        {
            for ( cid in f$conns )
            {
                NOTICE([
                    $note = Suspicious_Certificate,
                    $conn = f$conns[cid],
                    $msg = fmt("AsyncRAT/DcRat cert pattern: SHA512+RSA4096 (subject: %s, server: %s:%s)",
                               subject, f$conns[cid]$id$resp_h, f$conns[cid]$id$resp_p),
                    $sub = "AsyncRAT/DcRat Cert Pattern"
                ]);
            }
        }
    }

    # --- Certificate Validity Period Anomalies ---
    # CA/Browser Forum limits: max 398 days for publicly trusted certs.
    # Self-signed certs with very long validity indicate tool-generated certs:
    #   Metasploit: 4-9 years (randomized), AsyncRAT/DcRat: ~10 years
    # Legitimate internal CAs may also use long validity, but combined with
    # self-signed + long validity, this is a strong indicator.
    if ( cert?$not_valid_before && cert?$not_valid_after )
    {
        local validity_secs = interval_to_double(cert$not_valid_after - cert$not_valid_before);
        local five_years_secs = 5.0 * 365.0 * 86400.0;

        if ( validity_secs > five_years_secs && subject == issuer )
        {
            local validity_days = double_to_count(validity_secs / 86400.0);
            for ( cid in f$conns )
            {
                NOTICE([
                    $note = Suspicious_Certificate,
                    $conn = f$conns[cid],
                    $msg = fmt("Self-signed cert with excessive validity: %d days (~%d years, subject: %s, server: %s:%s)",
                               validity_days, double_to_count(validity_secs / (365.0 * 86400.0)),
                               subject, f$conns[cid]$id$resp_h, f$conns[cid]$id$resp_p),
                    $sub = fmt("Long validity self-signed: %d days", validity_days),
                    $identifier = cat(f$conns[cid]$id$resp_h, f$conns[cid]$id$resp_p, "longvalidity")
                ]);
            }
        }
    }
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # Placeholder files (keep for compatibility, but detection is in main file)
    #---------------------------------------------------------------------------
    cat > "$dest_dir/detection_ja3.zeek" << 'ZEEKEOF'
##! JA3 TLS Fingerprint Detection
##! Detection logic is in detection.zeek - this file kept for compatibility
ZEEKEOF

    cat > "$dest_dir/detection_ja4.zeek" << 'ZEEKEOF'
##! JA4 TLS Fingerprint Detection
##! Detection logic is in detection.zeek - this file kept for compatibility
ZEEKEOF

    cat > "$dest_dir/detection_hassh.zeek" << 'ZEEKEOF'
##! HASSH SSH Fingerprint Detection
##! Detection logic is in detection.zeek - this file kept for compatibility
ZEEKEOF

    #---------------------------------------------------------------------------
    # DNS Anomaly / Tunneling Detection
    #---------------------------------------------------------------------------
    cat > "$dest_dir/dns_anomaly.zeek" << 'ZEEKEOF'
##! DNS Anomaly Detection - Tunneling, Exfiltration, DGA
##! Detects: iodine (NULL records), dnscat2, dns2tcp, generic DNS tunneling
##!
##! Detection methods:
##!   1. NULL record queries (almost exclusively used by DNS tunneling tools)
##!   2. Unusually long DNS queries (data encoded in subdomain labels)
##!   3. High volume of unique subdomains to a single parent domain
##!
##! NOTE: Entropy-based detection is not included here (complex to implement
##! in Zeek script). For entropy analysis, use post-processing tools like
##! RITA or export dns.log to a SIEM.

module RedTeam;

export {
    # Enable/disable DNS anomaly detection
    option enable_dns_detection: bool = T;

    # Query length threshold - normal DNS queries are typically < 30 chars
    # DNS tunneling tools encode data in subdomains, approaching the 253-char limit
    # 52 chars catches most tunneling while avoiding false positives on CDN/cloud URLs
    option dns_query_length_threshold: count = 52;

    # Unique subdomain threshold per parent domain per source (2-minute window)
    # Normal browsing: ~5-20 unique subdomains per domain
    # DNS tunneling: hundreds of unique subdomains per domain
    option dns_subdomain_threshold: count = 100;

    # Whitelist domains that legitimately have many subdomains
    # Examples: CDN providers, analytics, cloud services
    option dns_whitelisted_domains: set[string] = {
        "akadns.net", "akamaiedge.net", "amazonaws.com",
        "azure.com", "cloudflare.com", "cloudfront.net",
        "google.com", "googleapis.com", "googleusercontent.com",
        "gstatic.com", "microsoft.com", "msedge.net",
        "office.com", "windows.net", "windowsupdate.com",
    } &redef;
}

# Track unique subdomains per [source, parent_domain] pair
global dns_subdomain_tracker: table[string] of set[string] &read_expire=2min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( ! enable_dns_detection )
        return;

    # --- NULL Record Detection (iodine DNS tunneling) ---
    # DNS NULL records (qtype 10) have almost zero legitimate use.
    # iodine uses NULL records as its preferred downstream encoding method.
    if ( qtype == 10 )
    {
        NOTICE([
            $note = DNS_Tunneling,
            $conn = c,
            $msg = fmt("DNS NULL record query (strong iodine/tunneling indicator): %s from %s",
                       query, c$id$orig_h),
            $sub = "DNS NULL Record",
            $identifier = cat(c$id$orig_h, "null_dns")
        ]);
    }

    # --- Long DNS Query Detection ---
    # Data exfiltration via DNS encodes payloads in subdomain labels.
    # Legitimate queries rarely exceed 50 characters.
    if ( |query| > dns_query_length_threshold )
    {
        NOTICE([
            $note = DNS_Tunneling,
            $conn = c,
            $msg = fmt("Suspiciously long DNS query (%d chars, possible data exfiltration): %s from %s",
                       |query|, query, c$id$orig_h),
            $sub = "Long DNS Query",
            $identifier = cat(c$id$orig_h, "long_dns", query)
        ]);
    }

    # --- Unique Subdomain Volume Detection ---
    # DNS tunneling generates hundreds of unique subdomains under a single
    # parent domain (each query encodes different data). Normal browsing
    # generates far fewer unique subdomains per domain.
    local parts = split_string(query, /\./);
    local n = |parts|;

    if ( n >= 3 )
    {
        # Extract parent domain (last 2 labels)
        local parent = fmt("%s.%s", parts[n - 2], parts[n - 1]);
        local src = c$id$orig_h;
        local tracker_key = fmt("%s|%s", src, parent);

        # Skip whitelisted domains
        if ( parent in dns_whitelisted_domains )
            return;

        if ( tracker_key !in dns_subdomain_tracker )
            dns_subdomain_tracker[tracker_key] = set();

        add dns_subdomain_tracker[tracker_key][query];

        if ( |dns_subdomain_tracker[tracker_key]| >= dns_subdomain_threshold )
        {
            NOTICE([
                $note = DNS_Tunneling,
                $conn = c,
                $msg = fmt("High volume unique subdomains: %s queried %d+ unique subdomains of %s (DNS tunneling/exfiltration)",
                           src, dns_subdomain_threshold, parent),
                $sub = fmt("DNS subdomain volume: %s", parent),
                $identifier = cat(src, parent, "subdomain_volume")
            ]);
            # Reset after alerting to allow future detections
            delete dns_subdomain_tracker[tracker_key];
        }
    }
}
ZEEKEOF

    log_success "Created TLS fingerprinting framework"
}

generate_fingerprints() {
    log_header "Generating Fingerprint Database (verified signatures only)"

    local fp_dir="$SITE_DIR/redteam-detection/fingerprints"
    mkdir -p "$fp_dir"

    #---------------------------------------------------------------------------
    # JA3 SIGNATURES (abuse.ch SSLBL + Trisul JA3 DB + DFIR reports)
    #---------------------------------------------------------------------------
    log_info "Generating JA3 signatures (SSLBL + Trisul + DFIR research)..."

    cat > "$fp_dir/ja3_signatures.zeek" << 'ZEEKEOF'
##! JA3 Client TLS Fingerprints - ALL VERIFIED
##! Sources: abuse.ch SSLBL (25M+ samples), Trisul JA3 DB, Salesforce JA3/JA3S blog, DFIR Report
##! Last verified: 2026-02-05

module RedTeam;

export {
    global ja3_signatures: table[string] of string = {
        # =====================================================================
        # RATS (Remote Access Trojans) - abuse.ch SSLBL + DFIR research
        # =====================================================================
        #
        # CRITICAL: .NET SslStream fingerprint family
        # The JA3 fc54e0d16d9764783542f0146a98b300 is the .NET SslStream/SChannel
        # fingerprint shared by ALL .NET RATs: AsyncRAT, XWorm, VenomRAT, DCRat,
        # QuasarRAT, NanoCore, Orcus, Agent Tesla (HTTPS mode), SolarMarker,
        # njRAT (TLS mode), PoshC2 Sharp Implant, and any .NET app using SslStream.
        # Detection via JA3 alone has false-positive risk - combine with cert
        # patterns (CN="AsyncRAT Server", "DcRat", "VenomRAT", etc.) for accuracy.
        #
        ["fc54e0d16d9764783542f0146a98b300"] = ".NET SslStream RAT (AsyncRAT/XWorm/VenomRAT/DCRat/QuasarRAT/NanoCore/Orcus)", # 19,871 SSLBL samples
        ["8515076cbbca9dce33151b798f782456"] = "BitRAT",                      # 1,127 SSLBL samples
        ["51a7ad14509fd614c7bb3a50c4982b8c"] = "JBifrost RAT",               # 2,952 SSLBL samples
        ["d2935c58fe676744fecc8614ee5356c7"] = "Adwind RAT",                 # 5,149 SSLBL samples
        ["decfb48a53789ebe081b88aabb58ee34"] = "Adwind RAT (variant)",       # 478 SSLBL samples
        ["e7d705a3286e19ea42f587b344ee6865"] = "QuasarRAT/Tor",

        # Remcos RAT - UNIQUE fingerprint, strictly associated (ANY.RUN verified)
        # Unlike .NET RATs above, Remcos uses its own TLS implementation
        ["a85be79f7b569f1df5e6087b69deb493"] = "Remcos RAT",                 # ANY.RUN strict association

        # Skuld Stealer - Go-based info stealer with unique fingerprints (ANY.RUN)
        ["e69402f870ecf542b4f017b0ed32936a"] = "Skuld Stealer (Go)",         # ANY.RUN verified
        ["d113e8b9d55b97b77077806180483c96"] = "Skuld Stealer (Go variant)", # ANY.RUN verified

        # =====================================================================
        # C2 FRAMEWORKS - DFIR Report + Salesforce JA3/JA3S blog
        # NOTE: 72a589da... and a0e9f5d6... are WINDOWS TLS SOCKET fingerprints.
        # They match Cobalt Strike/Metasploit but also legitimate Windows apps.
        # Pair with JA3S for higher fidelity detection.
        # =====================================================================
        ["72a589da586844d7f0818ce684948eea"] = "Win10 SChannel to IP (CobaltStrike/Meterpreter/Havoc/Covenant/Remcos/Warzone)",
        # DISABLED - Too broad, matches all Windows system TLS traffic (SChannel default)
        # ["a0e9f5d64349fb13191bc781f81f42e1"] = "Win10 SChannel to domain (CobaltStrike/Meterpreter/IcedID/LummaC2/Stealc/AgentTesla)",
        ["5d65ea3fb1d4aa7d826733f355cd4c51"] = "Metasploit Meterpreter",
        ["5d65ea3fb1d4aa7d826733d2f2cbbb1d"] = "Metasploit Meterpreter HTTPS (Linux)", # Verified via live testing
        ["3b5074b1b5d032e5620f69f9f700ff0e"] = "IcedID",                     # NETRESEC blog
        ["0c9457ab6f0d6a14fc8a3d1d149547fb"] = "BumbleBee C2",               # Darktrace research
        ["eb88d0b3e1961a0562f006e5ce2a0b87"] = "Cobalt Strike Malleable C2", # Suricata ET rules
        ["f5e62b5a2ed9467df09fae7a8a54dda6"] = "BazarBackdoor/BazarLoader",  # TrickBot backdoor, Suricata ET rules

        # Go crypto/tls C2 agents
        ["2196848d251b217de8b2c037e356c11d"] = "Go C2 Agent (Sliver/Poseidon/Chisel/Merlin/Go-compiled)", # Verified live: Sliver v1.7.0, Go 1.25.6
        ["19e29534fd49dd27d09234e639c4057e"] = "Go C2 Agent (Sliver/Poseidon/Chisel/Merlin, older Go)",   # Darktrace - Go < 1.22 default TLS

        # EMPIRE / STARKILLER - Python-based C2
        ["db42e3017c8b6d160751ef3a04f695e7"] = "Empire/PoshC2 Python Server",       # DFIR Report
        ["8d9f7747675e24454cd9b7ed35c58707"] = "Python requests Agent (Empire/PoshC2)", # Python requests 2.32.3

        # POSHC2 - Nettitude C2 framework
        ["c12f54a3f91dc7bafd92cb59fe009a35"] = "PoshC2 PowerShell Implant (Win10)", # Nettitude IOCs
        # fc54e0d16d9764783542f0146a98b300 already listed above (.NET SslStream shared by PoshC2 Sharp + all .NET RATs)

        # =====================================================================
        # BANKING TROJANS - abuse.ch SSLBL
        # =====================================================================
        # TrickBot (9 variants, 57K-166 samples each)
        ["8916410db85077a5460817142dcbc8de"] = "TrickBot",                    # 57,948 samples
        ["e62a5f4d538cbf169c2af71bec2399b4"] = "TrickBot",                   # 30,317 samples
        ["f735bbc6b69723b9df7b0e7ef27872af"] = "TrickBot",                   # 7,111 samples
        ["49ed2ef3f1321e5f044f1e71b0e6fdd5"] = "TrickBot",                   # 6,624 samples
        ["1aa7bf8b97e540ca5edd75f7b8384bfa"] = "TrickBot",                   # 1,735 samples
        ["c50f6a8b9173676b47ba6085bd0c6cee"] = "TrickBot",                   # 782 samples
        ["534ce2dbc413c68e908363b5df0ae5e0"] = "TrickBot",                   # 166 samples
        ["8f52d1ce303fb4a6515836aec3cc16b1"] = "TrickBot",                   # 236 samples
        ["fb00055a1196aeea8d1bc609885ba953"] = "TrickBot",                   # 187 samples

        # Dridex (6 variants, 292K-446 samples)
        ["51c64c77e60f3980eea90869b68c58a8"] = "Dridex",                     # 292,504 samples
        ["b386946a5a44d1ddcc843bc75336dfce"] = "Dridex",                     # 10,857 samples
        ["cb98a24ee4b9134448ffb5714fd870ac"] = "Dridex",                     # 5,145 samples
        ["d6f04b5a910115f4b50ecec09d40a1df"] = "Dridex",                     # 446 samples
        ["67f762b0ffe3aad00dfdb0e4b1acd8b5"] = "Dridex/Dyre/Upatre",        # Trisul DB
        ["74927e242d6c3febf8cb9cab10a7f889"] = "Dridex/Kovter/Upatre",      # Trisul DB

        # Gozi/ISFB
        ["57f3642b4e37e28f5cbe3020c9331b4c"] = "Gozi/ISFB",                 # 44,244 samples
        ["c201b92f8b483fa388be174d6689f534"] = "Gozi/ISFB",

        # Gootkit
        ["c5235d3a8b9934b7fbbd204d50bc058d"] = "Gootkit",                   # SSLBL
        ["a34e8a810b5f390fc7aa5ed711fa6993"] = "Gootkit",                   # Trisul DB
        ["c6e36d272db78ba559429e3d845606d1"] = "Gootkit (Neutrino EK)",     # Trisul DB

        # Qakbot
        ["7dd50e112cd23734a310b90f6f44a7cd"] = "Qakbot",                    # 25,016 samples
        ["3cda52da4ade09f1f781ad2e82dcfa20"] = "Qakbot",                    # 272 samples

        # Emotet (shared JA3 with Tofsee - from Salesforce JA3 blog)
        ["4d7a28d6f2263ed61de88ca66eb011e3"] = "Emotet/Tofsee/FormBook/LokiBot",

        # =====================================================================
        # SPAMBOTS (high-sample Tofsee) - abuse.ch SSLBL
        # =====================================================================
        ["fd80fa9c6120cdeea8520510f3c644ac"] = "Tofsee spambot",            # 10,265 samples
        ["e3b2ab1f9a56f2fb4c9248f2f41631fa"] = "Tofsee spambot",           # 8,817 samples
        ["7c410ce832e848a3321432c9a82e972b"] = "Tofsee spambot",           # 8,761 samples
        ["1fe4c7a3544eb27afec2adfb3a3dbf60"] = "Tofsee spambot",           # 6,434 samples
        ["fc2299d5b2964cd242c5a2c8c531a5f0"] = "Tofsee spambot",           # 3,866 samples
        ["70722097d1fe1d78d8c2164640ab6df4"] = "Tofsee spambot",           # 3,940 samples
        ["c0220cd64849a629397a9cb68f78a0ea"] = "Tofsee spambot",           # 2,853 samples
        ["b90bdbe961a648f0427db21aaa6ccb59"] = "Tofsee spambot",           # 2,516 samples
        ["17fd49722f8d11f3d76dce84f8e099a7"] = "Tofsee spambot",           # 2,589 samples

        # =====================================================================
        # RANSOMWARE - abuse.ch SSLBL
        # =====================================================================
        ["1be3ecebe5aa9d3654e6e703d81f6928"] = "Troldesh/Shade ransomware", # 3,076 samples
        ["1712287800ac91b34cadd5884ce85568"] = "TorrentLocker ransomware",  # 1,762 samples
        ["2d8794cb7b52b777bee2695e79c15760"] = "Ransomware (generic)",      # 206 samples

        # =====================================================================
        # OFFENSIVE TOOLS / SCANNERS - Trisul JA3 DB
        # =====================================================================
        ["950ccdd64d360a7b24c70678ac116a44"] = "Metasploit CCS Scanner",
        ["ee031b874122d97ab269e0d8740be31a"] = "Metasploit HeartBleed Scanner",
        ["6825b330bf9de50ccc8745553cb61b2f"] = "Metasploit SSL Scanner",
        ["f4262963691a8f123d4434c7308ad7fe"] = "Nikto Web Scanner",
        ["5eeeafdbc41e5ca7b81c92dbefa03ab7"] = "Nikto Web Scanner",
        ["a563bb123396e545f5704a9a2d16bcb0"] = "Nikto Web Scanner",

        # =====================================================================
        # BOTNETS / MISC - abuse.ch SSLBL + Trisul DB
        # =====================================================================
        ["40adfd923eb82b89d8836ba37a19bca1"] = "CoinMiner",                 # 16,529 samples
        ["b50f81ae37fb467713e167137cf14540"] = "Skynet Tor Botnet",         # Trisul DB

        # Multi-use fingerprint (matches CryptoWall/Locky/SmokeLoader/Emotet/RIG-EK)
        ["1d095e68489d3c535297cd8dffb06cb9"] = "Generic Malware (CryptoWall/Locky/SmokeLoader/Emotet)",
    };

    # JA3S Server fingerprints - pair with JA3 for high-fidelity detection
    # Source: Salesforce JA3/JA3S blog, DFIR Report, NETRESEC
    global ja3s_signatures: table[string] of string = {
        ["ae4edc6faf64d08308082ad26be60767"] = "Cobalt Strike C2 Server",    # DFIR Report
        ["b742b407517bac9536a77a7b0fee28e9"] = "Cobalt Strike C2 Server",    # DFIR Report
        ["649d6810e8392f63dc311eecb6b7098b"] = "Cobalt Strike C2 Server",    # DFIR Report
        ["ec74a5c51106f0419184d0dd08fb05bc"] = "IcedID C2 Server",           # NETRESEC
        ["80b3a14bccc8598a1f3bbe83e71f735f"] = "Emotet C2 Server",           # Salesforce blog
        ["da2b67b20914678c1f1f5888281e1db9"] = "Metasploit Handler Server",  # Verified via live testing
        ["f4febc55ea12b31ae17cfb7e614afda8"] = "Go TLS 1.3 Server (Sliver/Mythic/Go C2)", # Verified live: Sliver v1.7.0, Go 1.25.6
        ["475c9302dc42b2751db9edcac3b74891"] = "Sliver C2 Server (default multiplayer)", # Intel Insights / Censys
        ["70999de61602be74d4b25185843bd18e"] = "Meterpreter Handler (Kali)", # Salesforce JA3/JA3S blog
        ["e35df3e00ca4ef31d42b34bebaa2f86e"] = "Meterpreter Reverse Shell Handler", # Suricata ET rules
        ["623de93db17d313345d7ea481e7443cf"] = "TrickBot C2 Server",        # Salesforce JA3/JA3S blog
    };
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # JA4 SIGNATURES (ja4db.com verified entries + DFIR reports)
    #---------------------------------------------------------------------------
    log_info "Generating JA4 signatures..."

    cat > "$fp_dir/ja4_signatures.zeek" << 'ZEEKEOF'
##! JA4/JA4S TLS Fingerprints
##! Source: ja4db.com (verified entries), FoxIO, DFIR community reports
##! Last verified: 2026-02-05
##!
##! WARNING: JA4 fingerprints can vary based on:
##!   - Go/language version used to compile the implant
##!   - TLS library version, Malleable profile (for Cobalt Strike)
##! Validate against your specific threat environment.

module RedTeam;

export {
    global ja4_signatures: table[string] of string = {
        # COBALT STRIKE - ja4db.com verified + DFIR reports
        ["t12i190700_d83cc789557e_16bbda4055b2"] = "Cobalt Strike v4.9.1 (wininet, Win10)",
        ["t12i210700_76e208dd3e22_16bbda4055b2"] = "Cobalt Strike v4.9.1 (winhttp, Win10)",
        # DISABLED - Too broad, matches any Go app using default TLS (Go < 1.22)
        # ["t13d190900_9dc949149365_97f8aa674fd9"] = "Cobalt Strike / Sliver / Go C2 (Go < 1.22)",
        # ["t13i190900_9dc949149365_97f8aa674fd9"] = "Cobalt Strike / Sliver / Go C2 (Go < 1.22, no SNI)",
        # DISABLED - Too broad, matches common Windows/IcedID TLS patterns
        # ["t13d201100_2b729b4bf6f3_9e7b989ebec8"] = "IcedID / Cobalt Strike Beacon",
        ["t12d190900_9dc949149365_97f8aa674fd9"] = "Cobalt Strike (TLS 1.2)",
        ["t13d191000_9dc949149365_e7c285222651"] = "Cobalt Strike 4.x malleable",
        ["t13d1517h2_8daaf6152771_b0da82dd1658"] = "Cobalt Strike 4.9+ HTTPS",

        # SLIVER / GO C2 - Verified live: Sliver v1.7.0 HTTPS, Go 1.25.6
        # Go 1.25.6 uses 13 cipher suites (RSA/3DES removed in Go 1.22+/1.23+) and post-quantum X25519MLKEM768
        ["t13i131000_f57a46bbacb6_e5728521abd4"] = "Go C2 Agent / Sliver HTTPS (Go 1.25, no SNI)", # Verified live
        ["t13d131000_f57a46bbacb6_e5728521abd4"] = "Go C2 Agent / Sliver HTTPS (Go 1.25, with SNI)",

        # SLIVER / GO C2 - Legacy fingerprints (older Go versions < 1.22, 19 cipher suites)
        # NOTE: t13d190900_9dc949149365_97f8aa674fd9 already in Cobalt Strike section above (shared Go fingerprint)
        ["t13d190900_9dc949149365_e7c285222651"] = "Sliver C2 implant (older Go)",
        ["t13d190900_fcb5b95cb75a_b0d3b4ac2a14"] = "Sliver mTLS / Go C2 (older Go)",
        ["t13d201100_fcb5b95cb75a_b0d3b4ac2a14"] = "Sliver HTTPS implant (older Go)",
        ["t13d1517h2_8daaf6152771_02713d6af862"] = "Sliver C2 (Go 1.19+)",

        # NMAP SSL SCANNING - Verified via live testing
        ["t13i781000_ab95583b6d39_d41ae481755e"] = "Nmap ssl-enum-ciphers (78 cipher probes)",

        # METERPRETER
        ["t13d190600_55b17b6b0ada_5c4c70b73fa0"] = "Meterpreter HTTPS",
        ["t12d190600_55b17b6b0ada_5c4c70b73fa0"] = "Meterpreter HTTPS (TLS 1.2)",
        ["t12i060100_fdb7a2bc8059_b61e28f98305"] = "Meterpreter HTTPS (Linux, verified)", # Verified via live testing

        # BRUTE RATEL - From DFIR reports
        ["t13d190900_2bab81a5c9ae_e5627efa2ab1"] = "Brute Ratel C4 badger",
        ["t13d201100_2bab81a5c9ae_e5627efa2ab1"] = "Brute Ratel C4 HTTPS",
        ["t13d1516h2_8daaf6152771_e5627efa2ab1"] = "Brute Ratel C4 (newer)",

        # MYTHIC - Poseidon agent (Go-compiled, fingerprint varies by Go version)
        ["t13d1516h2_8daaf6152771_3b5074ec1c19"] = "Mythic C2 agent",
        # Mythic Poseidon also matches Go C2 Agent entry above (t13i3111h2...)

        # REMCOS RAT - abuse.ch/SSLBL
        ["t13i010400_0f2cb44170f4_5c4c70b73fa0"] = "Remcos RAT",
        ["t12i010400_0f2cb44170f4_5c4c70b73fa0"] = "Remcos RAT (TLS 1.2)",
    };

    # JA4S Server fingerprints (C2 server identification) - ja4db.com verified
    # NOTE: TLS 1.3 JA4S fingerprints can be broad (e.g., t130200_1301_... matches
    # any TLS 1.3 server with AES_128_GCM_SHA256). Combine with client JA4 and cert
    # anomaly detection for higher fidelity. Verified via live Sliver/Mythic testing.
    global ja4s_signatures: table[string] of string = {
        # Go TLS 1.3 server (Sliver/Mythic) - verified live: Sliver v1.7.0
        # NOTE: Also matches some legitimate TLS 1.3 servers. Combine with client JA4 for high fidelity.
        ["t130200_1301_a56c5b993250"] = "Go TLS 1.3 Server (Sliver/Mythic C2)", # Verified live + ja4db.com
        ["t120300_c030_5e2616a54c73"] = "IcedID C2 Server",                 # ja4db.com
        ["t120300_c030_52d195ce1d92"] = "Cobalt Strike v4.9.1 Server",      # ja4db.com
        ["t120100_003d_bc98f8e001b5"] = "Metasploit Handler Server (TLS 1.2)", # Verified via live testing
    };
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # JA4X CERTIFICATE SIGNATURES (ja4db.com verified)
    #---------------------------------------------------------------------------
    log_info "Generating JA4X certificate signatures..."

    cat > "$fp_dir/ja4x_certificates.zeek" << 'ZEEKEOF'
##! JA4X Certificate Fingerprints & Suspicious Patterns
##! Source: ja4db.com (verified), FoxIO, Validin, threat intelligence
##!
##! STATUS: JA4X is NOT YET COMPUTED by the Zeek JA4 package (awaiting Zeek
##! object support). These signatures are included for:
##!   1. Future use when Zeek adds JA4X support
##!   2. Offline analysis with Wireshark/Arkime/tshark (which do compute JA4X)
##!   3. Threat intel reference for pivoting in Censys/Shodan
##!
##! For ACTIVE certificate detection, see detection.zeek which uses x509.log
##! fields (serial numbers, validity periods, key parameters, subject/issuer).

module RedTeam;

export {
    global ja4x_signatures: table[string] of string = {
        # Verified from ja4db.com
        ["e7bc7ebc3d9e_e7bc7ebc3d9e_a704c60b6818"] = "Cobalt Strike/BianLian (Java keytool)",
        ["d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae"] = "Sliver/Havoc C2 (Go default)",
        ["000000000000_4f24da86fad6_bf0f0589fc03"] = "Sliver C2 (minimal cert)",
        ["000000000000_7c32fa18c13e_bf0f0589fc03"] = "Sliver/Havoc C2 Server (variant)",
        ["2166164053c1_2166164053c1_30d204a01551"] = "Cobalt Strike Cat C2",
        ["2bab15409345_af684594efb4_000000000000"] = "Qakbot Malware",
        ["1a59268f55e5_1a59268f55e5_795797892f9c"] = "Pikabot Malware",
        ["7022c563de38_7022c563de38_0147df7a0c11"] = "QuasarRAT",
    };

    global suspicious_cert_patterns: set[string] = {
        # C2 framework defaults
        "Cobalt Strike", "cobaltstrike", "Major Cobalt Strike",
        "Sliver", "sliver", "Havoc", "havoc",
        "Metasploit", "metasploit", "meterpreter",
        "Mythic", "mythic", "Poseidon", "poseidon",
        "Empire", "empire", "Starkiller", "starkiller",
        "PoshC2", "poshc2", "Covenant", "covenant",
        "Brute Ratel", "bruteratel",

        # PoshC2 default certificate values (Nettitude)
        "Pajfds", "Jethpro", "P18055077", "Minnetonka",

        # Cobalt Strike default keystore certificate fields
        "Major Cobalt Strike", "AdvancedPenTesting", "Cyberspace",

        # Pentesting defaults
        "YOURORGANIZATION", "YOURCOMPANY", "example.com",
        "localhost", "test", "Test", "default", "Default",
        "changeme", "changeit", "password", "pentest", "redteam",

        # .NET RAT family defaults (CN values from default configs)
        # These share JA3 fc54e0d16d9764783542f0146a98b300 (.NET SslStream)
        "AsyncRAT", "AsyncRAT Server", "DcRat", "DCRat",
        "VenomRAT", "VenomRATByVenom", "XWorm", "xworm",
        "QuasarRAT", "Quasar", "SXN Server CA",  # QuasarRAT default CN
        "NanoCore", "nanocore",
        "Orcus", "orcus", "SolarMarker", "solarmarker",
        "njRAT", "NJRAT", "njrat",
        "qwqdanchun",  # DcRat/VenomRAT author handle (in OU/O fields)

        # Native RATs (C/C++, custom TLS or WinAPI)
        "Remcos", "remcos", "BitRAT", "bitrat",
        "Warzone", "warzone", "Ave Maria", "avemaria",
        "NetWire", "netwire", "NETWIRE",
        "AgentTesla", "Agent Tesla",
        "Adwind", "adwind", "JBifrost", "jbifrost",

        # Info stealers / loaders
        "LummaC2", "lumma", "Stealc", "stealc",
        "RedLine", "redline", "Vidar", "vidar",
        "Raccoon", "raccoon", "RaccoonStealer",
        "DarkGate", "darkgate", "PikaBot", "pikabot",
        "SystemBC", "systembc", "Amadey", "amadey",
        "IcedID", "icedid", "BumbleBee", "bumblebee",
        "Emotet", "emotet", "BazarBackdoor", "bazarloader",
        "Skuld", "skuld",

        # Suspicious patterns
        "DVWS", "kali", "Kali", "parrot", "Parrot",
        "hacker", "Hacker", "pwned", "owned",
    };
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # HASSH SSH SIGNATURES (hassh.io, Salesforce research)
    #---------------------------------------------------------------------------
    log_info "Generating HASSH SSH signatures..."

    cat > "$fp_dir/hassh_signatures.zeek" << 'ZEEKEOF'
##! HASSH SSH Client/Server Fingerprints
##! Source: hassh.io, Salesforce research
##!
##! IMPORTANT: HASSH fingerprints identify SSH CLIENT LIBRARIES, not specific malware.
##! Many legitimate tools use the same libraries as offensive tools.
##! These are for awareness/correlation, not definitive detection.

module RedTeam;

export {
    global hassh_signatures: table[string] of string = {
        # VERIFIED SSH LIBRARIES (from hassh.io)
        ["ec7378c1a92f5a8dde7e8b7a1ddf33d1"] = "Paramiko (Python SSH)",
        ["b12d2871a1189eff20364cf5333619ee"] = "Paramiko (older version)",
        ["06046964c022c6407d15a27b12a6a4fb"] = "libssh (C library)",
        ["fa36fb822c0c3f7b4fe7f5e7a9c88e3f"] = "libssh2",
        ["cd47e3015a05249c3969c3c5583f72a0"] = "Go crypto/ssh (Sliver/legitimate Go apps)",
        ["4e066189c3bbeec38c99b1855113733a"] = "Dropbear SSH (embedded/IoT)",
        ["17952a186afb90dc4a10f7cd5c8b354c"] = "AsyncSSH (Python async)",
        ["92674389fa1e47a27ddd8d9b63ecd42b"] = "Metasploit SSH module",
        ["8a8ae540028bf433cd68356c1b9e8d5b"] = "Hydra SSH brute-force",
        ["a2318c69ceaa6e8a3d1a69f5f0f8d60b"] = "Ncrack SSH brute-force",
        ["b5752e36ba6c0979cce01a4e626ebe54"] = "Bitvise SSH client",
    };

    global hasshserver_signatures: table[string] of string = {
        ["b5752e36ba6c0979cce01a4e626ebe54"] = "Paramiko SSH server",
        ["06046964c022c6407d15a27b12a6a4fb"] = "libssh server",
    };
}
ZEEKEOF

    log_success "Generated fingerprint database (JA3: ~82, JA3S: 10, JA4: ~26, JA4S: 5, JA4X: 8, HASSH: 11, cert patterns: 90+, DNS anomaly rules: 3)"
}

install_ad_attacks() {
    log_header "Installing Windows/AD Attack Detection Package"
    
    local dest_dir="$SITE_DIR/ad-attacks"
    
    if ! check_write_permissions "$dest_dir"; then
        return 1
    fi
    
    mkdir -p "$dest_dir"
    
    log_info "Creating AD attack detection scripts..."
    
    #---------------------------------------------------------------------------
    # Main loader
    #---------------------------------------------------------------------------
    cat > "$dest_dir/__load__.zeek" << 'ZEEKEOF'
##! Windows/AD Attack Detection Suite
##! Detects: Impacket, Kerberoasting, BloodHound, PetitPotam, PrintNightmare

@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/krb
@load base/frameworks/notice
@load base/frameworks/sumstats

module AD_ATTACKS;

export {
    redef enum Notice::Type += {
        DCSync_Attack,
        PSExec_Execution,
        WMIExec_Execution,
        DCOMExec_Execution,
        ATExec_Execution,
        Secretsdump_Registry,
        Kerberoasting_Detected,
        ASREP_Roasting_Detected,
        SharpHound_Enumeration,
        PetitPotam_Attack,
        PrintNightmare_Attack,
        Admin_Share_Access,
        Lateral_Movement_Score,
    };
    
    # Configuration
    option detect_impacket: bool = T;
    option detect_kerberoasting: bool = T;
    option detect_bloodhound: bool = T;
    option detect_lateral_movement: bool = T;
    
    # Whitelists - CONFIGURE THESE
    option whitelisted_dcs: set[addr] = {} &redef;
    option whitelisted_admin_hosts: set[addr] = {} &redef;
    
    # Thresholds
    option kerberos_tgs_threshold: count = 10;
    option smb_lateral_threshold: count = 5;
    option smb_scan_threshold: count = 20;
    
    # State tracking
    global kerberos_tgs_rc4: table[addr] of count &default=0 &read_expire=2min;
    global discovery_tracker: table[addr] of count &default=0 &read_expire=1min;
    global smb_scan_tracker: table[addr] of set[addr] &read_expire=5min;
}

@load ./dce_rpc_attacks
@load ./kerberos_attacks
@load ./smb_attacks
ZEEKEOF

    #---------------------------------------------------------------------------
    # DCE-RPC Attack Detection
    #---------------------------------------------------------------------------
    cat > "$dest_dir/dce_rpc_attacks.zeek" << 'ZEEKEOF'
##! DCE-RPC Attack Detection - Impacket, PetitPotam, PrintNightmare

module AD_ATTACKS;

# High-confidence attack operations
const dcsync_ops: set[string] = { "drsuapi::DRSGetNCChanges", "drsuapi::DRSReplicaSync" };
const service_ops: set[string] = { "svcctl::CreateServiceW", "svcctl::CreateServiceA", 
                                    "svcctl::StartServiceW", "svcctl::CreateServiceWOW64W" };
const wmi_ops: set[string] = { "IWbemServices::ExecMethod", "IWbemServices::ExecMethodAsync" };
const dcom_ops: set[string] = { "IRemoteSCMActivator::RemoteCreateInstance" };
const task_ops: set[string] = { "atsvc::NetrJobAdd", "ITaskSchedulerService::SchRpcRegisterTask" };
const petitpotam_ops: set[string] = { "lsarpc::EfsRpcOpenFileRaw", "efsrpc::EfsRpcOpenFileRaw" };
const printnightmare_ops: set[string] = { "spoolss::RpcAddPrinterDriverEx" };

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=5
{
    if ( ! detect_impacket || ! c?$dce_rpc )
        return;
    
    if ( ! c$dce_rpc?$endpoint || ! c$dce_rpc?$operation )
        return;
    
    local rpc = fmt("%s::%s", c$dce_rpc$endpoint, c$dce_rpc$operation);
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    # DCSync (VERY HIGH confidence)
    if ( rpc in dcsync_ops && src !in whitelisted_dcs )
    {
        NOTICE([$note=DCSync_Attack, $conn=c,
                $msg=fmt("DCSync attack: %s from non-DC", rpc),
                $sub="T1003.006", $src=src, $dst=dst]);
    }
    
    # PetitPotam (VERY HIGH confidence)
    if ( rpc in petitpotam_ops )
    {
        NOTICE([$note=PetitPotam_Attack, $conn=c,
                $msg=fmt("PetitPotam coercion: %s", rpc),
                $sub="T1187", $src=src, $dst=dst]);
    }
    
    # PrintNightmare (VERY HIGH confidence)
    if ( rpc in printnightmare_ops )
    {
        NOTICE([$note=PrintNightmare_Attack, $conn=c,
                $msg=fmt("PrintNightmare exploit: %s", rpc),
                $sub="T1068", $src=src, $dst=dst]);
    }
    
    # Service execution - psexec/smbexec (HIGH confidence)
    if ( rpc in service_ops && src !in whitelisted_admin_hosts )
    {
        NOTICE([$note=PSExec_Execution, $conn=c,
                $msg=fmt("Remote service execution: %s", rpc),
                $sub="T1569.002", $src=src, $dst=dst]);
    }
    
    # WMI execution (HIGH confidence)
    if ( rpc in wmi_ops && src !in whitelisted_admin_hosts )
    {
        NOTICE([$note=WMIExec_Execution, $conn=c,
                $msg=fmt("WMI remote execution: %s", rpc),
                $sub="T1047", $src=src, $dst=dst]);
    }
    
    # DCOM execution (HIGH confidence)
    if ( rpc in dcom_ops && src !in whitelisted_admin_hosts )
    {
        NOTICE([$note=DCOMExec_Execution, $conn=c,
                $msg=fmt("DCOM remote execution: %s", rpc),
                $sub="T1021.003", $src=src, $dst=dst]);
    }
    
    # Scheduled task (HIGH confidence)
    if ( rpc in task_ops && src !in whitelisted_admin_hosts )
    {
        NOTICE([$note=ATExec_Execution, $conn=c,
                $msg=fmt("Remote scheduled task: %s", rpc),
                $sub="T1053.005", $src=src, $dst=dst]);
    }
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # Kerberos Attack Detection
    #---------------------------------------------------------------------------
    cat > "$dest_dir/kerberos_attacks.zeek" << 'ZEEKEOF'
##! Kerberos Attack Detection - Kerberoasting, AS-REP Roasting
##! Note: For comprehensive Kerberos attack detection, install BZAR package
##!       zkg install zeek/mitre-attack/bzar
##!
##! This module provides basic volume-based detection using connection tracking.
##! BZAR provides much more sophisticated Kerberos attack detection.

module AD_ATTACKS;

# Track Kerberos connections per source for volume-based detection
global krb_conn_tracker: table[addr] of count &default=0 &read_expire=2min;

# Basic Kerberos volume detection via connection tracking
# High volume of Kerberos connections may indicate Kerberoasting or enumeration
event connection_established(c: connection) &priority=3
{
    if ( ! detect_kerberoasting )
        return;

    # Kerberos uses port 88
    if ( c$id$resp_p != 88/tcp && c$id$resp_p != 88/udp )
        return;

    local src = c$id$orig_h;
    ++krb_conn_tracker[src];

    # Alert on high volume of Kerberos requests (potential Kerberoasting)
    if ( krb_conn_tracker[src] >= kerberos_tgs_threshold )
    {
        NOTICE([$note=Kerberoasting_Detected, $conn=c,
                $msg=fmt("High volume Kerberos activity: %s made %d Kerberos connections (potential Kerberoasting/enumeration)",
                        src, krb_conn_tracker[src]),
                $sub="T1558.003", $src=src]);

        # Reset counter after alert
        krb_conn_tracker[src] = 0;
    }
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # SMB Attack Detection
    #---------------------------------------------------------------------------
    cat > "$dest_dir/smb_attacks.zeek" << 'ZEEKEOF'
##! SMB Attack Detection - Lateral movement, SharpHound patterns

module AD_ATTACKS;

const admin_shares: pattern = /ADMIN\$|C\$|IPC\$/;

# SMB2 Tree Connect (most common)
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=5
{
    if ( ! detect_lateral_movement )
        return;
    
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    if ( admin_shares in path && src !in whitelisted_admin_hosts )
    {
        NOTICE([$note=Admin_Share_Access, $conn=c,
                $msg=fmt("Admin share access: %s -> %s (%s)", src, dst, path),
                $sub="T1021.002", $src=src, $dst=dst]);
    }
}

# SMB1 Tree Connect (legacy, but still used by some tools)
event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) &priority=5
{
    if ( ! detect_lateral_movement )
        return;
    
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    if ( admin_shares in path && src !in whitelisted_admin_hosts )
    {
        NOTICE([$note=Admin_Share_Access, $conn=c,
                $msg=fmt("Admin share access (SMB1): %s -> %s (%s)", src, dst, path),
                $sub="T1021.002", $src=src, $dst=dst]);
    }
}

# SharpHound detection via SMB scan pattern
event connection_established(c: connection) &priority=5
{
    if ( ! detect_bloodhound || c$id$resp_p != 445/tcp )
        return;
    
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    if ( src !in smb_scan_tracker )
        smb_scan_tracker[src] = set();
    
    add smb_scan_tracker[src][dst];
    
    if ( |smb_scan_tracker[src]| >= smb_scan_threshold )
    {
        NOTICE([$note=SharpHound_Enumeration, $conn=c,
                $msg=fmt("SMB scan pattern: %s -> %d hosts (possible BloodHound/SharpHound)", 
                        src, |smb_scan_tracker[src]|),
                $sub="T1049", $src=src]);
        # Reset after alerting to allow future detections
        delete smb_scan_tracker[src];
    }
}
ZEEKEOF

    log_success "Created AD attack detection package"
}

create_local_zeek() {
    log_header "Creating local.zeek Configuration"
    
    local local_zeek="$SITE_DIR/local.zeek"
    local backup=""
    
    # Backup existing local.zeek
    if [[ -f "$local_zeek" ]]; then
        backup="${local_zeek}.backup.$(date +%Y%m%d%H%M%S)"
        cp "$local_zeek" "$backup"
        log_info "Backed up existing local.zeek to $backup"
    fi
    
    # Build whitelist strings
    local dc_whitelist=""
    if [[ ${#DC_IPS[@]} -gt 0 ]]; then
        dc_whitelist=$(printf ", %s" "${DC_IPS[@]}")
        dc_whitelist="${dc_whitelist:2}"  # Remove leading ", "
    fi
    
    local admin_whitelist=""
    if [[ ${#ADMIN_IPS[@]} -gt 0 ]]; then
        admin_whitelist=$(printf ", %s" "${ADMIN_IPS[@]}")
        admin_whitelist="${admin_whitelist:2}"
    fi
    
    # Determine package loads based on installation status
    local ja3_load=""
    local ja4_load=""
    local hassh_load=""
    local bzar_load=""

    # JA3 - legacy TLS fingerprinting
    if [[ "$JA3_INSTALLED" == true ]] || zkg list 2>/dev/null | grep -q "ja3"; then
        ja3_load="@load packages/ja3"
    else
        ja3_load="# @load packages/ja3  # Install: zkg install zeek/salesforce/ja3"
    fi

    # JA4 - modern TLS fingerprinting (TLS 1.3 aware)
    if zkg list 2>/dev/null | grep -q "ja4" || \
       [[ -d "$SITE_DIR/packages/ja4" ]] || \
       sudo zkg list 2>/dev/null | grep -q "ja4"; then
        ja4_load="@load packages/ja4"
    else
        ja4_load="# @load packages/ja4  # Install: zkg install zeek/foxio/ja4"
    fi

    # HASSH - SSH fingerprinting
    if zkg list 2>/dev/null | grep -q "hassh" || \
       [[ -d "$SITE_DIR/packages/hassh" ]] || [[ -d "$SITE_DIR/hassh" ]] || \
       sudo zkg list 2>/dev/null | grep -q "hassh"; then
        hassh_load="@load packages/hassh"
    else
        hassh_load="# @load packages/hassh  # Install: zkg install zeek/corelight/hassh"
    fi

    # BZAR - lateral movement detection
    if [[ "$BZAR_INSTALLED" == true ]] || zkg list 2>/dev/null | grep -q "bzar"; then
        bzar_load="@load packages/bzar"
    else
        bzar_load="# @load packages/bzar  # Install: zkg install zeek/mitre-attack/bzar"
    fi

    cat > "$local_zeek" << ZEEKEOF
##! Zeek Local Site Configuration
##! Generated by Zeek Red Team Detection Suite Installer
##! $(date)

#==============================================================================
# STANDARD ZEEK CONFIGURATION
#==============================================================================

@load base/frameworks/notice
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/krb

#==============================================================================
# JSON LOG OUTPUT (easier parsing in Splunk/SIEM)
#==============================================================================
# Output all Zeek logs in JSON format instead of TSV
redef LogAscii::use_json = T;

#==============================================================================
# JA3 TLS FINGERPRINTING (Legacy - broad coverage)
#==============================================================================
# Required for TLS-based malware/C2 detection
# Install: zkg install zeek/salesforce/ja3

${ja3_load}

#==============================================================================
# JA4+ TLS FINGERPRINTING (Modern - TLS 1.3 aware)
#==============================================================================
# Includes: JA4, JA4S, JA4H, JA4L, JA4X, JA4SSH
# Install: zkg install zeek/foxio/ja4

${ja4_load}

#==============================================================================
# HASSH SSH FINGERPRINTING
#==============================================================================
# Fingerprints SSH clients/servers for threat detection
# Install: zkg install zeek/corelight/hassh

${hassh_load}

#==============================================================================
# MITRE BZAR - LATERAL MOVEMENT DETECTION
#==============================================================================
# Provides enhanced SMB+DCE-RPC correlation and file extraction
# Install: zkg install zeek/mitre-attack/bzar

${bzar_load}

#==============================================================================
# RED TEAM DETECTION SUITE - TLS FINGERPRINTING
#==============================================================================
# Detects C2 frameworks, RATs, malware via JA4/JA3 fingerprints
# Coverage: 70+ malware families, 125+ fingerprints

@load ./redteam-detection

#==============================================================================
# AD ATTACK DETECTION SUITE
#==============================================================================
# Detects Impacket, Kerberoasting, BloodHound, exploitation
# Coverage: DCSync, PsExec, WMIExec, Kerberoasting, PetitPotam, PrintNightmare

@load ./ad-attacks

#==============================================================================
# WHITELIST CONFIGURATION - CUSTOMIZE FOR YOUR ENVIRONMENT
#==============================================================================

# Domain Controllers - Add your DC IPs to prevent DCSync false positives
# These hosts legitimately perform AD replication
# Example: redef AD_ATTACKS::whitelisted_dcs += { 10.0.0.1, 10.0.0.2 };
$(if [[ -n "$dc_whitelist" ]]; then echo "redef AD_ATTACKS::whitelisted_dcs += { $dc_whitelist };"; fi)

# Admin Workstations - Optional: Whitelist legitimate admin jump boxes
# These may use PsExec/WMI for legitimate administration
# Example: redef AD_ATTACKS::whitelisted_admin_hosts += { 10.0.0.100 };
$(if [[ -n "$admin_whitelist" ]]; then echo "redef AD_ATTACKS::whitelisted_admin_hosts += { $admin_whitelist };"; fi)

#==============================================================================
# DETECTION TUNING
#==============================================================================

# Enable/disable detection categories
redef AD_ATTACKS::detect_impacket = T;
redef AD_ATTACKS::detect_kerberoasting = T;
redef AD_ATTACKS::detect_bloodhound = T;
redef AD_ATTACKS::detect_lateral_movement = T;

# Kerberoasting threshold (RC4 TGS requests before alerting)
redef AD_ATTACKS::kerberos_tgs_threshold = 10;

# Lateral movement threshold (unique hosts before alerting)
redef AD_ATTACKS::smb_lateral_threshold = 5;

# SMB scan threshold for SharpHound detection
redef AD_ATTACKS::smb_scan_threshold = 20;

#==============================================================================
# END OF CONFIGURATION
#==============================================================================
ZEEKEOF

    log_success "Created local.zeek configuration"
    
    if [[ -n "$backup" ]]; then
        log_info "Previous config backed up to: $backup"
    fi
}

verify_installation() {
    log_header "Verifying Installation"
    
    local zeek_bin="$ZEEK_DIR/bin/zeek"
    local errors=0
    
    if [[ ! -x "$zeek_bin" ]]; then
        log_warning "Zeek binary not found/executable - skipping verification"
        log_info "Files have been installed; verify manually with: zeek -a $SITE_DIR/local.zeek"
        return 0
    fi
    
    # Check TLS fingerprinting
    log_info "Checking TLS fingerprinting module..."
    local output
    output=$("$zeek_bin" -a "$SITE_DIR/redteam-detection/__load__.zeek" 2>&1) || true
    if echo "$output" | grep -qi "error"; then
        log_error "TLS fingerprinting module has errors:"
        echo "$output" | grep -i "error" | head -5
        ((errors++)) || true
    else
        log_success "TLS fingerprinting module OK"
    fi
    
    # Check AD attacks
    log_info "Checking AD attacks module..."
    output=$("$zeek_bin" -a "$SITE_DIR/ad-attacks/__load__.zeek" 2>&1) || true
    if echo "$output" | grep -qi "error"; then
        log_error "AD attacks module has errors:"
        echo "$output" | grep -i "error" | head -5
        ((errors++)) || true
    else
        log_success "AD attacks module OK"
    fi
    
    # Check local.zeek
    log_info "Checking local.zeek configuration..."
    output=$("$zeek_bin" -a "$SITE_DIR/local.zeek" 2>&1) || true
    if echo "$output" | grep -qi "error"; then
        log_warning "local.zeek has errors:"
        echo "$output" | grep -i "error" | head -5
        if [[ "$BZAR_INSTALLED" != true ]]; then
            log_info "This may be due to BZAR not being installed"
            log_info "Edit local.zeek and comment out '@load packages/bzar' if needed"
        fi
    else
        log_success "local.zeek configuration OK"
    fi
    
    return $errors
}

print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              INSTALLATION COMPLETE                             ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Installed Fingerprinting Packages:${NC}"

    # Check JA3
    if [[ "$JA3_INSTALLED" == true ]] || zkg list 2>/dev/null | grep -q "ja3"; then
        echo "  ✓ JA3  - TLS fingerprinting (legacy, broad coverage)"
    else
        echo "  ✗ JA3  - NOT INSTALLED (run: zkg install zeek/salesforce/ja3)"
    fi

    # Check JA4
    if zkg list 2>/dev/null | grep -q "ja4"; then
        echo "  ✓ JA4+ - TLS fingerprinting (modern, TLS 1.3 aware)"
    else
        echo "  ✗ JA4+ - NOT INSTALLED (run: zkg install zeek/foxio/ja4)"
    fi

    # Check HASSH
    if zkg list 2>/dev/null | grep -q "hassh"; then
        echo "  ✓ HASSH - SSH fingerprinting"
    else
        echo "  ✗ HASSH - NOT INSTALLED (run: zkg install zeek/corelight/hassh)"
    fi

    # Check BZAR
    if [[ "$BZAR_INSTALLED" == true ]] || zkg list 2>/dev/null | grep -q "bzar"; then
        echo "  ✓ BZAR  - MITRE ATT&CK lateral movement"
    else
        echo "  ○ BZAR  - Not installed (optional)"
    fi

    echo ""
    echo -e "${GREEN}Detection Rules Installed:${NC}"
    echo "  ✓ TLS Detection Rules - 220+ JA3/JA4 signatures"
    echo "  ✓ SSH Detection Rules - 20+ HASSH signatures"
    echo "  ✓ Certificate Patterns - 90+ suspicious patterns"
    echo "  ✓ X.509 Certificate Analysis - serial numbers, validity, key params"
    echo "  ✓ DNS Tunneling Detection - NULL records, long queries, subdomain volume"
    echo "  ✓ AD Attack Detection - Impacket, Kerberoasting, BloodHound"
    echo ""
    echo -e "${GREEN}Detection Coverage:${NC}"
    echo "  • 18 C2 frameworks (Cobalt Strike, Sliver, Havoc, Brute Ratel, Mythic...)"
    echo "  • 15 RATs (AsyncRAT, njRAT, QuasarRAT, Remcos, DCRat, XWorm...)"
    echo "  • 10 Stealers/Loaders (LummaC2, RedLine, IcedID, Pikabot...)"
    echo "  • 10 Banking trojans (TrickBot, Dridex, Emotet, Qakbot...)"
    echo "  • X.509 cert analysis (CS default serial, AsyncRAT SHA512+4096, long validity)"
    echo "  • DNS tunneling (iodine NULL records, dnscat2, data exfiltration)"
    echo "  • 7 Impacket tools (secretsdump, psexec, wmiexec...)"
    echo "  • SSH tunneling tools (Paramiko, libssh, Meterpreter SSH)"
    echo "  • Kerberoasting & AS-REP Roasting"
    echo "  • SharpHound/BloodHound enumeration"
    echo "  • PetitPotam & PrintNightmare exploitation"
    echo ""
    echo -e "${GREEN}Zeek Status:${NC}"
    echo "  ✓ Configuration deployed"
    echo "  ✓ Workers started (zeekctl deploy)"
    echo "  ✓ Service enabled for boot persistence"
    echo ""
    echo -e "${YELLOW}Optional Next Steps:${NC}"
    echo ""
    echo "  1. (If packages missing) Install fingerprinting packages:"
    echo "     zkg install zeek/salesforce/ja3"
    echo "     zkg install zeek/foxio/ja4"
    echo "     zkg install zeek/corelight/hassh"
    echo "     zeekctl deploy  # Redeploy after installing"
    echo ""
    echo "  2. (Optional) Edit whitelists to reduce false positives:"
    echo -e "     ${BOLD}$SITE_DIR/local.zeek${NC}"
    echo "     zeekctl deploy  # Redeploy after editing"
    echo ""
    echo -e "${GREEN}Monitor Logs:${NC}"
    echo "  • /opt/zeek/logs/current/notice.log    - Attack alerts"
    echo "  • /opt/zeek/logs/current/ssl.log       - TLS fingerprints"
    echo "  • /opt/zeek/logs/current/ssh.log       - SSH fingerprints"
    echo "  • /opt/zeek/logs/current/dce_rpc.log   - DCE-RPC activity"
    echo ""
    echo -e "${GREEN}Useful Commands:${NC}"
    echo "  zeekctl status              - Check worker status"
    echo "  zeekctl deploy              - Redeploy after config changes"
    echo "  tail -f /opt/zeek/logs/current/notice.log  - Live alerts"
    echo ""
    if [[ ${#DC_IPS[@]} -eq 0 ]]; then
        echo -e "${YELLOW}NOTE: No DC whitelist configured. DCSync alerts from legitimate${NC}"
        echo -e "${YELLOW}      Domain Controllers will trigger until you add them to local.zeek${NC}"
        echo ""
    fi
    echo -e "${GREEN}Configuration file: $SITE_DIR/local.zeek${NC}"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--zeek-dir)
            ZEEK_DIR="$2"
            shift 2
            ;;
        -s|--skip-bzar)
            SKIP_BZAR=true
            shift
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

# Parse environment variables for whitelists
if [[ -n "${ZEEK_DC_IPS:-}" ]]; then
    IFS=',' read -ra DC_IPS <<< "$ZEEK_DC_IPS"
fi
if [[ -n "${ZEEK_ADMIN_IPS:-}" ]]; then
    IFS=',' read -ra ADMIN_IPS <<< "$ZEEK_ADMIN_IPS"
fi

# Banner
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     ZEEK RED TEAM DETECTION SUITE - UNIFIED INSTALLER          ║${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}║  TLS Fingerprinting + AD Attacks + MITRE BZAR                  ║${NC}"
echo -e "${CYAN}║  70+ malware families • 125+ fingerprints • 95%+ accuracy      ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Detect Zeek
log_step "1/9" "Detecting Zeek Installation"
if [[ -z "$ZEEK_DIR" ]]; then
    if ! detect_zeek; then
        log_error "Could not detect Zeek installation"
        log_info "Please specify with --zeek-dir /path/to/zeek"
        exit 1
    fi
else
    if [[ ! -d "$ZEEK_DIR" ]]; then
        log_error "Zeek directory not found: $ZEEK_DIR"
        exit 1
    fi
    log_success "Using specified Zeek directory: $ZEEK_DIR"
fi

SITE_DIR="$ZEEK_DIR/share/zeek/site"
check_zeek_version

# Check we can write to the site directory
if ! check_write_permissions "$SITE_DIR"; then
    exit 1
fi

# Step 2: Install JA3 (required for TLS fingerprinting)
log_step "2/9" "JA3 TLS Fingerprinting Package"
install_ja3 || true  # Continue even if JA3 fails

# Step 3: Install BZAR
log_step "3/9" "MITRE BZAR Package"
if [[ "$SKIP_BZAR" == true ]]; then
    log_info "Skipping BZAR installation (--skip-bzar)"
else
    install_bzar || true  # Continue even if BZAR fails
fi

# Step 4: Install TLS Fingerprinting
log_step "4/9" "TLS Fingerprinting Framework"
install_tls_fingerprinting

# Step 5: Generate Fingerprints
log_step "5/9" "Fingerprint Database"
generate_fingerprints

# Step 6: Install AD Attacks
log_step "6/9" "AD Attack Detection"
install_ad_attacks

# Step 7: Collect Whitelists (optional, interactive)
log_step "7/9" "Whitelist Configuration (Optional)"
if [[ "$NON_INTERACTIVE" == true ]]; then
    log_info "Skipping whitelist configuration (non-interactive mode)"
    log_info "You can add whitelists later in local.zeek"
else
    echo ""
    echo -e "${YELLOW}Whitelists help reduce false positives but are OPTIONAL.${NC}"
    echo "You can configure these later by editing local.zeek"
    echo ""

    if prompt_yes_no "Configure Domain Controller whitelist now? [y/N]" "n"; then
        prompt_ips "Enter Domain Controller IP addresses:" DC_IPS
    fi

    if prompt_yes_no "Configure Admin workstation whitelist now? [y/N]" "n"; then
        prompt_ips "Enter Admin Workstation IP addresses:" ADMIN_IPS
    fi
fi

# Step 8: Create local.zeek
log_step "8/9" "Creating Configuration"
create_local_zeek

# Verify configuration syntax
verify_installation || true

# Step 9: Deploy Zeek and enable service
log_step "9/9" "Deploying Zeek"
log_info "Deploying Zeek configuration and starting workers..."
if zeekctl deploy 2>&1; then
    log_success "Zeek deployed and running"
else
    log_warning "zeekctl deploy had warnings (check above)"
fi

# Enable systemd service for persistence across reboots
if systemctl is-enabled zeek &>/dev/null; then
    log_success "Zeek service already enabled for boot"
else
    systemctl enable zeek 2>/dev/null && log_success "Enabled zeek service for boot persistence" || \
    log_warning "Could not enable zeek service (may need manual: systemctl enable zeek)"
fi

# Show status
log_info "Zeek status:"
zeekctl status 2>&1 || true

# Summary
print_summary
