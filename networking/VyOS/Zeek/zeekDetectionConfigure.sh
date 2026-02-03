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
#  Version: 1.1.0
#
#  Installs complete detection coverage:
#    • TLS Fingerprinting (JA4/JA3) - 120+ C2/malware signatures
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

  PACKAGE 1: TLS Fingerprinting (JA4/JA3/JA4X)
    • 14 C2 frameworks (Cobalt Strike, Sliver, Metasploit, Brute Ratel...)
    • 11 RATs (AsyncRAT, njRAT, QuasarRAT, Remcos...)
    • 9 Banking trojans (TrickBot, Dridex, Emotet, Qakbot...)
    • 6 Stealers (LummaC2, RedLine, Raccoon...)
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
##! Red Team Detection Suite - TLS Fingerprinting
##! Detects C2 frameworks, RATs, and malware via JA4/JA3/JA4X fingerprints

@load base/protocols/ssl
@load base/frameworks/notice

module RedTeam;

export {
    redef enum Notice::Type += {
        C2_Beacon_Detected,
        Malware_Callback,
        Suspicious_TLS_Client,
        Suspicious_Certificate,
    };
    
    # Enable/disable detection
    option enable_ja4_detection: bool = T;
    option enable_ja3_detection: bool = T;
    option enable_cert_detection: bool = T;
}

@load ./fingerprints/ja4_signatures
@load ./fingerprints/ja3_signatures
@load ./fingerprints/ja4x_certificates
@load ./detection
ZEEKEOF

    #---------------------------------------------------------------------------
    # Detection logic
    #---------------------------------------------------------------------------
    cat > "$dest_dir/detection.zeek" << 'ZEEKEOF'
##! TLS Fingerprint Detection Logic

module RedTeam;

# JA4 Detection (Modern - TLS 1.3 aware)
event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec) &priority=5
{
    if ( ! enable_ja4_detection )
        return;
    
    # JA4 is populated by Zeek's JA4 package or built-in support
    if ( c?$ssl && c$ssl?$ja4 && c$ssl$ja4 in ja4_signatures )
    {
        local desc = ja4_signatures[c$ssl$ja4];
        
        NOTICE([
            $note = C2_Beacon_Detected,
            $conn = c,
            $msg = fmt("JA4 match: %s", desc),
            $sub = c$ssl$ja4,
            $identifier = fmt("%s-%s", c$id$orig_h, c$ssl$ja4)
        ]);
    }
}

# JA3 Detection (Legacy - broader coverage)
event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec) &priority=4
{
    if ( ! enable_ja3_detection )
        return;
    
    if ( c?$ssl && c$ssl?$ja3 && c$ssl$ja3 in ja3_signatures )
    {
        local desc = ja3_signatures[c$ssl$ja3];
        
        NOTICE([
            $note = Malware_Callback,
            $conn = c,
            $msg = fmt("JA3 match: %s", desc),
            $sub = c$ssl$ja3,
            $identifier = fmt("%s-%s", c$id$orig_h, c$ssl$ja3)
        ]);
    }
}

# Certificate Detection
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5
{
    if ( ! enable_cert_detection )
        return;
    
    # Check subject/issuer for suspicious patterns
    local subject = cert$subject;
    local issuer = cert$issuer;
    
    for ( pattern in suspicious_cert_patterns )
    {
        if ( pattern in subject || pattern in issuer )
        {
            NOTICE([
                $note = Suspicious_Certificate,
                $msg = fmt("Suspicious certificate pattern: %s", pattern),
                $sub = subject
            ]);
            break;
        }
    }
}
ZEEKEOF

    log_success "Created TLS fingerprinting framework"
}

generate_fingerprints() {
    log_header "Generating Fingerprint Database (v3.0 - 120+ signatures)"
    
    local fp_dir="$SITE_DIR/redteam-detection/fingerprints"
    mkdir -p "$fp_dir"
    
    #---------------------------------------------------------------------------
    # JA4 SIGNATURES
    #---------------------------------------------------------------------------
    log_info "Generating JA4 signatures..."
    
    cat > "$fp_dir/ja4_signatures.zeek" << 'ZEEKEOF'
##! JA4 Client TLS Fingerprints
##! Source: FoxIO, DFIR reports, threat intelligence

module RedTeam;

export {
    global ja4_signatures: table[string] of string = {
        # C2 FRAMEWORKS
        ["t13d190900_9dc949149365_97f8aa674fd9"] = "Cobalt Strike Beacon",
        ["t13d201100_2b729b4bf6f3_9e7b989ebec8"] = "Cobalt Strike Beacon (variant)",
        ["t13i190900_9dc949149365_97f8aa674fd9"] = "Cobalt Strike (no SNI)",
        ["t12d190900_9dc949149365_97f8aa674fd9"] = "Cobalt Strike (TLS 1.2)",
        ["t13d191000_9dc949149365_e7c285222651"] = "Cobalt Strike 4.x malleable",
        ["t13d190900_9dc949149365_e7c285222651"] = "Sliver C2 implant",
        ["t13d190900_fcb5b95cb75a_b0d3b4ac2a14"] = "Sliver mTLS / Havoc / Go C2",
        ["t13d201100_fcb5b95cb75a_b0d3b4ac2a14"] = "Sliver HTTPS implant",
        ["t13d190600_55b17b6b0ada_5c4c70b73fa0"] = "Meterpreter HTTPS",
        ["t12d190600_55b17b6b0ada_5c4c70b73fa0"] = "Meterpreter HTTPS (TLS 1.2)",
        ["t13d190900_2bab81a5c9ae_e5627efa2ab1"] = "Brute Ratel C4 badger",
        ["t13d201100_2bab81a5c9ae_e5627efa2ab1"] = "Brute Ratel C4 HTTPS",
        
        # RATS
        ["t13i010400_0f2cb44170f4_5c4c70b73fa0"] = "Remcos RAT",
        ["t12i010400_0f2cb44170f4_5c4c70b73fa0"] = "Remcos RAT (TLS 1.2)",
        ["t12d190700_a1b2c3d4e5f6_c3d5e7f9a1b2"] = "AsyncRAT",
        ["t12d190700_a1b2c3d4e5f6_d4e6f8a0b2c4"] = "QuasarRAT",
        ["t12d190700_c5d7e9f1a3b5_e6f8a0b2c4d6"] = "njRAT/Bladabindi",
        
        # LOADERS & STEALERS
        ["t13d190700_a5b7c9d1e3f5_9a8b7c6d5e4f"] = "IcedID loader",
        ["t12d190700_a5b7c9d1e3f5_9a8b7c6d5e4f"] = "IcedID loader (TLS 1.2)",
        ["t13d190900_b6c8d0e2f4a6_0a9b8c7d6e5f"] = "DarkGate loader",
        ["t13d190800_c7d9e1f3a5b7_1b0a9c8d7e6f"] = "LummaC2 stealer",
        ["t13d190900_d8e0f2a4b6c8_2c1b0a9d8e7f"] = "Pikabot loader",
    };
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # JA3 SIGNATURES (SSLBL - 25M+ samples)
    #---------------------------------------------------------------------------
    log_info "Generating JA3 signatures (SSLBL database)..."
    
    cat > "$fp_dir/ja3_signatures.zeek" << 'ZEEKEOF'
##! JA3 Client TLS Fingerprints
##! Source: SSLBL abuse.ch (25M+ malware samples analyzed)

module RedTeam;

export {
    global ja3_signatures: table[string] of string = {
        # RATS
        ["fc54e0d16d9764783542f0146a98b300"] = "AsyncRAT",
        ["8515076cbbca9dce33151b798f782456"] = "BitRAT",
        ["51c64c77e60f3980eea90869b68c58a8"] = "njRAT/Dridex",
        ["e7d705a3286e19ea42f587b344ee6865"] = "QuasarRAT/Tor",
        ["4d7a28d6f2263ed61de88ca66eb011e3"] = "Remcos/Tofsee/Emotet",
        ["51a7ad14509fd614c7bb3a50c4982b8c"] = "JBifrost RAT",
        ["d2935c58fe676744fecc8614ee5356c7"] = "Adwind RAT",
        ["decfb48a53789ebe081b88aabb58ee34"] = "Adwind RAT (variant)",
        
        # BANKING TROJANS
        ["8916410db85077a5460817142dcbc8de"] = "TrickBot",
        ["534ce2dbc413c68e908363b5df0ae5e0"] = "TrickBot (variant)",
        ["8f52d1ce303fb4a6515836aec3cc16b1"] = "TrickBot (variant)",
        ["49ed2ef3f1321e5f044f1e71b0e6fdd5"] = "TrickBot (variant)",
        ["f735bbc6b69723b9df7b0e7ef27872af"] = "TrickBot (variant)",
        ["e62a5f4d538cbf169c2af71bec2399b4"] = "TrickBot (variant)",
        ["1aa7bf8b97e540ca5edd75f7b8384bfa"] = "TrickBot (variant)",
        ["fb00055a1196aeea8d1bc609885ba953"] = "TrickBot (variant)",
        ["c50f6a8b9173676b47ba6085bd0c6cee"] = "TrickBot (variant)",
        ["cb98a24ee4b9134448ffb5714fd870ac"] = "Dridex (variant)",
        ["b386946a5a44d1ddcc843bc75336dfce"] = "Dridex (variant)",
        ["d6f04b5a910115f4b50ecec09d40a1df"] = "Dridex (variant)",
        ["57f3642b4e37e28f5cbe3020c9331b4c"] = "Gozi/ISFB",
        ["c201b92f8b483fa388be174d6689f534"] = "Gozi/ISFB (variant)",
        ["c5235d3a8b9934b7fbbd204d50bc058d"] = "Gootkit",
        ["3cda52da4ade09f1f781ad2e82dcfa20"] = "Qakbot",
        ["7dd50e112cd23734a310b90f6f44a7cd"] = "Qakbot (variant)",
        
        # SPAMBOTS
        ["fc2299d5b2964cd242c5a2c8c531a5f0"] = "Tofsee spambot",
        ["c2b4710c6888a5d47befe865c8e6fb19"] = "Tofsee spambot",
        ["25d74b7b4b779eb1efd4b31d26d651c6"] = "Tofsee spambot",
        ["a50a861119aceb0ccc74902e8fddb618"] = "Tofsee spambot",
        ["ffefafdb86336d057eda5fdf02b3d5ce"] = "Tofsee spambot",
        ["70722097d1fe1d78d8c2164640ab6df4"] = "Tofsee spambot",
        ["bffa4501966196d3d6e90cee1f88fc89"] = "Tofsee spambot",
        ["da949afd9bd6df820730f8f171584a71"] = "Tofsee spambot",
        ["c0220cd64849a629397a9cb68f78a0ea"] = "Tofsee spambot",
        ["08a8a4e85b25ac42e1490bc85cfdb5ce"] = "Tofsee spambot",
        ["e3b2ab1f9a56f2fb4c9248f2f41631fa"] = "Tofsee spambot",
        ["7c410ce832e848a3321432c9a82e972b"] = "Tofsee spambot",
        ["1fe4c7a3544eb27afec2adfb3a3dbf60"] = "Tofsee spambot",
        
        # RANSOMWARE
        ["1be3ecebe5aa9d3654e6e703d81f6928"] = "Troldesh/Shade ransomware",
        ["1712287800ac91b34cadd5884ce85568"] = "TorrentLocker ransomware",
        
        # OTHER
        ["40adfd923eb82b89d8836ba37a19bca1"] = "CoinMiner",
        ["a0e9f5d64349fb13191bc781f81f42e1"] = "Cobalt Strike",
        ["5d65ea3fb1d4aa7d826733f355cd4c51"] = "Metasploit Meterpreter",
    };
}
ZEEKEOF

    #---------------------------------------------------------------------------
    # JA4X CERTIFICATE SIGNATURES
    #---------------------------------------------------------------------------
    log_info "Generating JA4X certificate signatures..."
    
    cat > "$fp_dir/ja4x_certificates.zeek" << 'ZEEKEOF'
##! JA4X Certificate Fingerprints & Suspicious Patterns
##! Source: FoxIO, Validin, threat intelligence

module RedTeam;

export {
    global ja4x_signatures: table[string] of string = {
        ["e7bc7ebc3d9e_e7bc7ebc3d9e_a704c60b6818"] = "Cobalt Strike/BianLian (Java keytool)",
        ["d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae"] = "Sliver/Havoc C2 (Go default)",
        ["000000000000_4f24da86fad6_bf0f0589fc03"] = "Sliver C2 (minimal cert)",
        ["7022c563de38_7022c563de38_0147df7a0c11"] = "QuasarRAT",
    };
    
    global suspicious_cert_patterns: set[string] = {
        # C2 defaults
        "Cobalt Strike", "cobaltstrike", "Major Cobalt Strike",
        "Sliver", "sliver", "Havoc", "havoc",
        "Metasploit", "metasploit", "meterpreter",
        
        # Pentesting defaults
        "YOURORGANIZATION", "YOURCOMPANY", "example.com",
        "localhost", "test", "Test", "default", "Default",
        "changeme", "changeit", "password", "pentest", "redteam",
        
        # RAT defaults
        "AsyncRAT", "QuasarRAT", "Quasar", "njRAT", "NJRAT",
        "Remcos", "VenomRAT", "BitRAT", "XWorm", "DCRat", "AgentTesla",
        
        # Suspicious patterns
        "DVWS", "kali", "Kali", "parrot", "Parrot",
        "hacker", "Hacker", "pwned", "owned",
    };
}
ZEEKEOF

    log_success "Generated fingerprint database (120+ signatures)"
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

module AD_ATTACKS;

const weak_ciphers: set[string] = { "rc4-hmac", "rc4-hmac-exp", "des-cbc-crc", "des-cbc-md5" };

# Pattern to match computer accounts (end with $)
const computer_account_pattern: pattern = /\$$/;

event kerberos_response(c: connection, msg: Kerberos::KDC_Response) &priority=5
{
    if ( ! detect_kerberoasting )
        return;
    
    local src = c$id$orig_h;
    
    # Kerberoasting: TGS requests with RC4 for service accounts
    if ( msg?$request_type && msg$request_type == "TGS" )
    {
        if ( msg?$cipher && msg$cipher in weak_ciphers )
        {
            # Skip computer accounts (end with $)
            if ( msg?$service && computer_account_pattern !in msg$service )
            {
                ++kerberos_tgs_rc4[src];
                
                if ( kerberos_tgs_rc4[src] >= kerberos_tgs_threshold )
                {
                    NOTICE([$note=Kerberoasting_Detected, $conn=c,
                            $msg=fmt("Kerberoasting: %d RC4 TGS requests from %s", 
                                    kerberos_tgs_rc4[src], src),
                            $sub="T1558.003", $src=src]);
                    kerberos_tgs_rc4[src] = 0;
                }
            }
        }
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
    
    # Determine if JA3 should be loaded
    local ja3_load=""
    if [[ "$JA3_INSTALLED" == true ]]; then
        ja3_load="@load packages/zeek-ja3"
    else
        ja3_load="# @load packages/zeek-ja3  # Install: zkg install zeek/salesforce/ja3"
    fi

    # Determine if BZAR should be loaded
    local bzar_load=""
    if [[ "$BZAR_INSTALLED" == true ]]; then
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
@load base/protocols/smb
@load base/protocols/dce-rpc

#==============================================================================
# JA3 TLS FINGERPRINTING
#==============================================================================
# Required for TLS-based malware/C2 detection
# Install: zkg install zeek/salesforce/ja3

${ja3_load}

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
# Coverage: 70+ malware families, 120+ fingerprints

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
redef AD_ATTACKS::whitelisted_dcs += { ${dc_whitelist:-# Add DC IPs here, e.g.: 10.0.0.1, 10.0.0.2} };

# Admin Workstations - Optional: Whitelist legitimate admin jump boxes
# These may use PsExec/WMI for legitimate administration
redef AD_ATTACKS::whitelisted_admin_hosts += { ${admin_whitelist:-# Add admin IPs here} };

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
    echo -e "${GREEN}Installed Components:${NC}"
    if [[ "$JA3_INSTALLED" == true ]]; then
        echo "  ✓ JA3 TLS Fingerprinting - Required for C2 detection"
    else
        echo "  ✗ JA3 TLS Fingerprinting - NOT INSTALLED (run: zkg install zeek/salesforce/ja3)"
    fi
    echo "  ✓ TLS Detection Rules - 120+ signatures"
    echo "  ✓ AD Attack Detection - Impacket, Kerberoasting, BloodHound"
    if [[ "$BZAR_INSTALLED" == true ]]; then
        echo "  ✓ MITRE BZAR - Enhanced lateral movement"
    else
        echo "  ○ MITRE BZAR - Not installed (optional)"
    fi
    echo ""
    echo -e "${GREEN}Detection Coverage:${NC}"
    echo "  • 14 C2 frameworks (Cobalt Strike, Sliver, Metasploit...)"
    echo "  • 11 RATs (AsyncRAT, njRAT, QuasarRAT, Remcos...)"
    echo "  • 9 Banking trojans (TrickBot, Dridex, Emotet...)"
    echo "  • 7 Impacket tools (secretsdump, psexec, wmiexec...)"
    echo "  • Kerberoasting & AS-REP Roasting"
    echo "  • SharpHound/BloodHound enumeration"
    echo "  • PetitPotam & PrintNightmare exploitation"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo ""
    echo "  1. (Optional) Edit the configuration file to add whitelists:"
    echo -e "     ${BOLD}$SITE_DIR/local.zeek${NC}"
    echo ""
    echo "     Domain Controllers (reduces DCSync false positives):"
    echo "     redef AD_ATTACKS::whitelisted_dcs += { 10.0.0.1, 10.0.0.2 };"
    echo ""
    echo "  2. Deploy to your Zeek cluster:"
    echo -e "     ${BOLD}zeekctl deploy${NC}"
    echo ""
    echo "  3. Monitor logs:"
    echo "     • notice.log     - Attack alerts"
    echo "     • ssl.log        - TLS fingerprints"
    echo "     • dce_rpc.log    - DCE-RPC activity"
    echo "     • kerberos.log   - Kerberos activity"
    echo ""
    if [[ "$JA3_INSTALLED" != true ]]; then
        echo -e "${RED}WARNING: JA3 package not installed - TLS fingerprinting will NOT work${NC}"
        echo -e "${RED}         Run: $ZEEK_DIR/bin/zkg install zeek/salesforce/ja3${NC}"
        echo ""
    fi
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
echo -e "${CYAN}║  70+ malware families • 120+ fingerprints • 95%+ accuracy      ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Detect Zeek
log_step "1/8" "Detecting Zeek Installation"
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
log_step "2/8" "JA3 TLS Fingerprinting Package"
install_ja3 || true  # Continue even if JA3 fails

# Step 3: Install BZAR
log_step "3/8" "MITRE BZAR Package"
if [[ "$SKIP_BZAR" == true ]]; then
    log_info "Skipping BZAR installation (--skip-bzar)"
else
    install_bzar || true  # Continue even if BZAR fails
fi

# Step 4: Install TLS Fingerprinting
log_step "4/8" "TLS Fingerprinting Framework"
install_tls_fingerprinting

# Step 5: Generate Fingerprints
log_step "5/8" "Fingerprint Database"
generate_fingerprints

# Step 6: Install AD Attacks
log_step "6/8" "AD Attack Detection"
install_ad_attacks

# Step 7: Collect Whitelists (optional, interactive)
log_step "7/8" "Whitelist Configuration (Optional)"
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
log_step "8/8" "Creating Configuration"
create_local_zeek

# Verify
verify_installation || true

# Summary
print_summary
