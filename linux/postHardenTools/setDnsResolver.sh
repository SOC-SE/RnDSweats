#!/bin/bash
# =============================================================================
# DNS RESOLVER CONFIGURATION TOOL
# Handles: systemd-resolved, NetworkManager, netplan, resolvconf, direct edit
# Provides cross-distro compatibility for setting custom DNS servers
# =============================================================================
set -uo pipefail

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- GLOBAL VARS ---
PRIMARY_DNS=""
SECONDARY_DNS=""
DNS_METHOD=""
BACKUP_DIR="/var/backup/dns-config-$(date +%Y%m%d-%H%M%S)"
DRY_RUN=false
FORCE=false
VERBOSE=false

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           DNS RESOLVER CONFIGURATION TOOL                     ║"
    echo "║     Cross-Distribution Linux DNS Configuration Utility        ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info()    { echo -e "${BLUE}[i]${NC} $1"; }
print_debug()   { [[ "$VERBOSE" == true ]] && echo -e "${CYAN}[D]${NC} $1"; }

usage() {
    echo "Usage: $0 -p PRIMARY_DNS [-s SECONDARY_DNS] [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  -p, --primary DNS      Primary DNS server IP address"
    echo ""
    echo "Optional:"
    echo "  -s, --secondary DNS    Secondary DNS server IP address"
    echo "  -m, --method METHOD    Force a specific method:"
    echo "                           systemd, networkmanager, netplan,"
    echo "                           resolvconf, direct"
    echo "  -d, --dry-run          Show what would be done without making changes"
    echo "  -f, --force            Skip confirmation prompts"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -p 10.0.0.5 -s 10.0.0.6"
    echo "  $0 -p 192.168.1.10 --method systemd"
    echo "  $0 -p 8.8.8.8 -s 8.8.4.4 --dry-run"
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (sudo)"
        exit 1
    fi
}

validate_ip() {
    local ip="$1"
    local valid_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ ! $ip =~ $valid_regex ]]; then
        return 1
    fi

    # Validate each octet
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ $octet -gt 255 ]]; then
            return 1
        fi
    done

    return 0
}

create_backup() {
    local file="$1"
    if [[ -e "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        local backup_name
        backup_name=$(echo "$file" | tr '/' '_')
        cp -a "$file" "$BACKUP_DIR/${backup_name}"
        print_debug "Backed up $file to $BACKUP_DIR/${backup_name}"
    fi
}

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

detect_dns_method() {
    print_info "Detecting DNS configuration method..."

    # Check what's managing /etc/resolv.conf
    local resolv_target=""
    if [[ -L /etc/resolv.conf ]]; then
        resolv_target=$(readlink -f /etc/resolv.conf 2>/dev/null || true)
        print_debug "/etc/resolv.conf is a symlink to: $resolv_target"
    fi

    # Detection priority order (most specific to least)

    # 1. Check for systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if [[ "$resolv_target" == *"systemd"* ]] || [[ "$resolv_target" == *"stub-resolv"* ]]; then
            DNS_METHOD="systemd-resolved"
            print_success "Detected: systemd-resolved (active, managing resolv.conf)"
            return 0
        elif [[ -f /etc/systemd/resolved.conf ]]; then
            DNS_METHOD="systemd-resolved"
            print_success "Detected: systemd-resolved (active)"
            return 0
        fi
    fi

    # 2. Check for NetworkManager
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        # Check if NM is managing DNS
        local nm_dns_mode=""
        if [[ -f /etc/NetworkManager/NetworkManager.conf ]]; then
            nm_dns_mode=$(grep -i "^dns=" /etc/NetworkManager/NetworkManager.conf 2>/dev/null | cut -d= -f2 || true)
        fi

        # If NM uses systemd-resolved as backend, prefer systemd method
        if [[ "$nm_dns_mode" == "systemd-resolved" ]]; then
            DNS_METHOD="systemd-resolved"
            print_success "Detected: NetworkManager with systemd-resolved backend"
            return 0
        fi

        DNS_METHOD="networkmanager"
        print_success "Detected: NetworkManager"
        return 0
    fi

    # 3. Check for netplan (Ubuntu 18.04+)
    if command -v netplan &>/dev/null && [[ -d /etc/netplan ]]; then
        local netplan_files
        netplan_files=$(find /etc/netplan -name "*.yaml" -o -name "*.yml" 2>/dev/null | head -1)
        if [[ -n "$netplan_files" ]]; then
            DNS_METHOD="netplan"
            print_success "Detected: netplan"
            return 0
        fi
    fi

    # 4. Check for resolvconf
    if command -v resolvconf &>/dev/null && [[ -d /etc/resolvconf ]]; then
        DNS_METHOD="resolvconf"
        print_success "Detected: resolvconf"
        return 0
    fi

    # 5. Check for dhclient hooks
    if [[ -f /etc/dhcp/dhclient.conf ]] || [[ -d /etc/dhcp/dhclient.d ]]; then
        # Check if dhclient is actively managing
        if pgrep -x dhclient &>/dev/null; then
            DNS_METHOD="dhclient"
            print_success "Detected: dhclient (active)"
            return 0
        fi
    fi

    # 6. Fallback to direct /etc/resolv.conf editing
    DNS_METHOD="direct"
    print_warning "No DNS manager detected, will edit /etc/resolv.conf directly"
    return 0
}

get_distro_info() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_debug "Distro: $NAME $VERSION_ID"
    fi
}

# =============================================================================
# CONFIGURATION METHODS
# =============================================================================

# --- SYSTEMD-RESOLVED ---
configure_systemd_resolved() {
    print_info "Configuring systemd-resolved..."

    local resolved_conf="/etc/systemd/resolved.conf"
    local resolved_dir="/etc/systemd/resolved.conf.d"

    create_backup "$resolved_conf"

    # Create drop-in directory for cleaner configuration
    mkdir -p "$resolved_dir"

    local dns_line="DNS=${PRIMARY_DNS}"
    [[ -n "$SECONDARY_DNS" ]] && dns_line="${dns_line} ${SECONDARY_DNS}"

    local config_content="# Custom DNS configuration - managed by setDnsResolver.sh
[Resolve]
${dns_line}
FallbackDNS=
DNSStubListener=yes
DNSSEC=no
"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would write to $resolved_dir/custom-dns.conf:"
        echo "$config_content"
        return 0
    fi

    echo "$config_content" > "$resolved_dir/custom-dns.conf"
    print_success "Created $resolved_dir/custom-dns.conf"

    # Ensure /etc/resolv.conf points to systemd stub
    local stub_path="/run/systemd/resolve/stub-resolv.conf"
    if [[ -e "$stub_path" ]] && [[ "$(readlink -f /etc/resolv.conf 2>/dev/null)" != "$stub_path" ]]; then
        create_backup /etc/resolv.conf
        ln -sf "$stub_path" /etc/resolv.conf
        print_success "Linked /etc/resolv.conf to systemd stub resolver"
    fi

    # Restart systemd-resolved
    print_info "Restarting systemd-resolved..."
    systemctl restart systemd-resolved

    # Verify
    sleep 1
    if resolvectl status &>/dev/null; then
        print_debug "resolvectl status:"
        resolvectl status 2>/dev/null | grep -E "(DNS Server|Current DNS)" | head -5
    fi

    print_success "systemd-resolved configured"
    return 0
}

# --- NETWORKMANAGER ---
configure_networkmanager() {
    print_info "Configuring NetworkManager..."

    # Get active connection
    local active_conn
    active_conn=$(nmcli -t -f NAME,DEVICE,STATE connection show --active 2>/dev/null | grep ":activated" | head -1 | cut -d: -f1)

    if [[ -z "$active_conn" ]]; then
        # Try alternative method
        active_conn=$(nmcli -t -f NAME connection show --active 2>/dev/null | head -1)
    fi

    if [[ -z "$active_conn" ]]; then
        print_error "No active NetworkManager connection found"
        print_info "Falling back to direct method..."
        configure_direct
        return $?
    fi

    print_debug "Active connection: $active_conn"

    local dns_servers="$PRIMARY_DNS"
    [[ -n "$SECONDARY_DNS" ]] && dns_servers="${dns_servers},${SECONDARY_DNS}"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would run:"
        echo "  nmcli connection modify \"$active_conn\" ipv4.dns \"$dns_servers\""
        echo "  nmcli connection modify \"$active_conn\" ipv4.ignore-auto-dns yes"
        echo "  nmcli connection up \"$active_conn\""
        return 0
    fi

    # Configure DNS
    nmcli connection modify "$active_conn" ipv4.dns "$dns_servers"
    nmcli connection modify "$active_conn" ipv4.ignore-auto-dns yes

    print_info "Reactivating connection..."
    nmcli connection up "$active_conn" &>/dev/null || true

    print_success "NetworkManager configured for connection: $active_conn"
    return 0
}

# --- NETPLAN ---
configure_netplan() {
    print_info "Configuring netplan..."

    # Find the primary netplan config
    local netplan_file
    netplan_file=$(find /etc/netplan -name "*.yaml" -o -name "*.yml" 2>/dev/null | sort | head -1)

    if [[ -z "$netplan_file" ]]; then
        print_error "No netplan configuration file found"
        print_info "Falling back to direct method..."
        configure_direct
        return $?
    fi

    print_debug "Using netplan file: $netplan_file"
    create_backup "$netplan_file"

    # Build DNS addresses string
    local dns_addresses="[${PRIMARY_DNS}"
    [[ -n "$SECONDARY_DNS" ]] && dns_addresses="${dns_addresses}, ${SECONDARY_DNS}"
    dns_addresses="${dns_addresses}]"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would modify $netplan_file to add:"
        echo "  nameservers:"
        echo "    addresses: $dns_addresses"
        return 0
    fi

    # Check if nameservers section exists in any interface
    if grep -q "nameservers:" "$netplan_file"; then
        # Update existing nameservers - this is tricky with YAML
        # Use a more careful approach with sed
        print_warning "Existing nameservers found in $netplan_file"
        print_info "Creating override file instead..."
    fi

    # Create an override file for DNS (cleaner approach)
    local override_file="/etc/netplan/99-custom-dns.yaml"

    # We need to determine the interface name from existing config
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)

    if [[ -z "$iface" ]]; then
        iface="eth0"  # fallback
    fi

    # Determine if using ethernets or wifis
    local net_type="ethernets"
    if [[ "$iface" == wl* ]] || [[ "$iface" == wlan* ]]; then
        net_type="wifis"
    fi

    cat > "$override_file" << EOF
# Custom DNS configuration - managed by setDnsResolver.sh
network:
  version: 2
  ${net_type}:
    ${iface}:
      nameservers:
        addresses: ${dns_addresses}
      dhcp4-overrides:
        use-dns: false
EOF

    print_success "Created $override_file"

    # Apply netplan
    print_info "Applying netplan configuration..."
    if ! netplan apply 2>&1; then
        print_error "Failed to apply netplan configuration"
        print_info "Restoring backup and trying direct method..."
        rm -f "$override_file"
        configure_direct
        return $?
    fi

    print_success "Netplan configured"
    return 0
}

# --- RESOLVCONF ---
configure_resolvconf() {
    print_info "Configuring resolvconf..."

    local head_file="/etc/resolvconf/resolv.conf.d/head"
    local base_file="/etc/resolvconf/resolv.conf.d/base"

    # Prefer head file (prepended to resolv.conf)
    local target_file="$head_file"
    if [[ ! -d "$(dirname "$head_file")" ]]; then
        target_file="$base_file"
    fi

    mkdir -p "$(dirname "$target_file")"
    create_backup "$target_file"

    local dns_content="# Custom DNS configuration - managed by setDnsResolver.sh
nameserver ${PRIMARY_DNS}"
    [[ -n "$SECONDARY_DNS" ]] && dns_content="${dns_content}
nameserver ${SECONDARY_DNS}"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would write to $target_file:"
        echo "$dns_content"
        return 0
    fi

    echo "$dns_content" > "$target_file"
    print_success "Created $target_file"

    # Update resolv.conf
    print_info "Updating resolv.conf via resolvconf..."
    resolvconf -u

    print_success "resolvconf configured"
    return 0
}

# --- DHCLIENT ---
configure_dhclient() {
    print_info "Configuring dhclient..."

    local dhclient_conf="/etc/dhcp/dhclient.conf"
    create_backup "$dhclient_conf"

    local dns_line="prepend domain-name-servers ${PRIMARY_DNS}"
    [[ -n "$SECONDARY_DNS" ]] && dns_line="${dns_line}, ${SECONDARY_DNS}"
    dns_line="${dns_line};"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would add to $dhclient_conf:"
        echo "  $dns_line"
        return 0
    fi

    # Remove any existing prepend domain-name-servers line
    if [[ -f "$dhclient_conf" ]]; then
        sed -i '/^prepend domain-name-servers/d' "$dhclient_conf"
        # Also remove our marker comment if present
        sed -i '/# Custom DNS - managed by setDnsResolver/d' "$dhclient_conf"
    fi

    # Add our configuration
    echo "# Custom DNS - managed by setDnsResolver.sh" >> "$dhclient_conf"
    echo "$dns_line" >> "$dhclient_conf"

    print_success "Updated $dhclient_conf"

    # Also update resolv.conf directly for immediate effect
    print_info "Updating /etc/resolv.conf for immediate effect..."
    configure_direct_internal

    print_success "dhclient configured"
    return 0
}

# --- DIRECT /etc/resolv.conf ---
configure_direct_internal() {
    # Internal function - doesn't do backups or full checks
    local resolv_content="# Custom DNS configuration - managed by setDnsResolver.sh
# WARNING: This file may be overwritten by DHCP or other services
nameserver ${PRIMARY_DNS}"
    [[ -n "$SECONDARY_DNS" ]] && resolv_content="${resolv_content}
nameserver ${SECONDARY_DNS}"

    # Remove immutable flag if present
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Handle symlink
    if [[ -L /etc/resolv.conf ]]; then
        rm -f /etc/resolv.conf
    fi

    echo "$resolv_content" > /etc/resolv.conf
}

configure_direct() {
    print_info "Configuring /etc/resolv.conf directly..."

    create_backup /etc/resolv.conf

    local resolv_content="# Custom DNS configuration - managed by setDnsResolver.sh
# Generated: $(date)
nameserver ${PRIMARY_DNS}"
    [[ -n "$SECONDARY_DNS" ]] && resolv_content="${resolv_content}
nameserver ${SECONDARY_DNS}"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would write to /etc/resolv.conf:"
        echo "$resolv_content"
        print_info "[DRY-RUN] Would set immutable flag on /etc/resolv.conf"
        return 0
    fi

    # Remove immutable flag if present
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Handle symlink - need to remove it first
    if [[ -L /etc/resolv.conf ]]; then
        print_warning "/etc/resolv.conf is a symlink, removing..."
        rm -f /etc/resolv.conf
    fi

    echo "$resolv_content" > /etc/resolv.conf
    print_success "Updated /etc/resolv.conf"

    # Make immutable to prevent DHCP/other services from overwriting
    if chattr +i /etc/resolv.conf 2>/dev/null; then
        print_success "Set immutable flag on /etc/resolv.conf"
        print_warning "To modify later, run: chattr -i /etc/resolv.conf"
    else
        print_warning "Could not set immutable flag (filesystem may not support it)"
        print_info "DNS settings may be overwritten by DHCP on next lease renewal"
    fi

    return 0
}

# =============================================================================
# VERIFICATION
# =============================================================================

verify_dns_config() {
    print_info "Verifying DNS configuration..."
    echo ""

    # Check /etc/resolv.conf content
    echo -e "${CYAN}Current /etc/resolv.conf:${NC}"
    if [[ -L /etc/resolv.conf ]]; then
        echo -e "  ${YELLOW}(symlink to: $(readlink -f /etc/resolv.conf))${NC}"
    fi
    grep "^nameserver" /etc/resolv.conf 2>/dev/null | while read -r line; do
        echo "  $line"
    done
    echo ""

    # Test DNS resolution
    echo -e "${CYAN}Testing DNS resolution:${NC}"
    local test_domains=("google.com" "cloudflare.com")
    local success=0

    for domain in "${test_domains[@]}"; do
        if result=$(nslookup "$domain" "$PRIMARY_DNS" 2>&1 | grep -A1 "Name:" | tail -1); then
            print_success "$domain resolved via $PRIMARY_DNS"
            ((success++))
        elif result=$(dig +short "$domain" "@$PRIMARY_DNS" 2>&1) && [[ -n "$result" ]]; then
            print_success "$domain resolved via $PRIMARY_DNS: $result"
            ((success++))
        elif result=$(host "$domain" "$PRIMARY_DNS" 2>&1) && [[ $? -eq 0 ]]; then
            print_success "$domain resolved via $PRIMARY_DNS"
            ((success++))
        else
            print_warning "Could not resolve $domain via $PRIMARY_DNS"
        fi
    done

    echo ""
    if [[ $success -gt 0 ]]; then
        print_success "DNS configuration verified successfully"
        return 0
    else
        print_error "DNS resolution test failed"
        print_info "The DNS server may not be reachable or not responding"
        return 1
    fi
}

show_current_config() {
    echo -e "${CYAN}Current DNS Configuration:${NC}"
    echo ""

    echo -e "  ${YELLOW}/etc/resolv.conf:${NC}"
    if [[ -L /etc/resolv.conf ]]; then
        echo -e "    Symlink to: $(readlink -f /etc/resolv.conf 2>/dev/null || echo 'unknown')"
    fi
    if [[ -f /etc/resolv.conf ]] || [[ -L /etc/resolv.conf ]]; then
        grep "^nameserver\|^search\|^domain" /etc/resolv.conf 2>/dev/null | sed 's/^/    /'
    else
        echo "    (file does not exist)"
    fi
    echo ""

    # systemd-resolved status
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "  ${YELLOW}systemd-resolved:${NC} active"
        resolvectl status 2>/dev/null | grep -E "DNS Server|Current DNS" | head -3 | sed 's/^/    /'
        echo ""
    fi

    # NetworkManager status
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo -e "  ${YELLOW}NetworkManager:${NC} active"
        nmcli dev show 2>/dev/null | grep -i "IP4.DNS" | head -2 | sed 's/^/    /'
        echo ""
    fi
}

# =============================================================================
# MAIN
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--primary)
                PRIMARY_DNS="$2"
                shift 2
                ;;
            -s|--secondary)
                SECONDARY_DNS="$2"
                shift 2
                ;;
            -m|--method)
                case "$2" in
                    systemd|systemd-resolved)
                        DNS_METHOD="systemd-resolved"
                        ;;
                    nm|networkmanager|NetworkManager)
                        DNS_METHOD="networkmanager"
                        ;;
                    netplan)
                        DNS_METHOD="netplan"
                        ;;
                    resolvconf)
                        DNS_METHOD="resolvconf"
                        ;;
                    dhclient)
                        DNS_METHOD="dhclient"
                        ;;
                    direct)
                        DNS_METHOD="direct"
                        ;;
                    *)
                        print_error "Unknown method: $2"
                        print_info "Valid methods: systemd, networkmanager, netplan, resolvconf, dhclient, direct"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            --show)
                show_current_config
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

main() {
    print_banner

    parse_args "$@"

    # Validate required arguments
    if [[ -z "$PRIMARY_DNS" ]]; then
        print_error "Primary DNS server is required"
        echo ""
        usage
    fi

    # Validate IP addresses
    if ! validate_ip "$PRIMARY_DNS"; then
        print_error "Invalid primary DNS IP address: $PRIMARY_DNS"
        exit 1
    fi

    if [[ -n "$SECONDARY_DNS" ]] && ! validate_ip "$SECONDARY_DNS"; then
        print_error "Invalid secondary DNS IP address: $SECONDARY_DNS"
        exit 1
    fi

    check_root
    get_distro_info

    # Show current config
    show_current_config

    # Detect method if not specified
    if [[ -z "$DNS_METHOD" ]]; then
        detect_dns_method
    else
        print_info "Using specified method: $DNS_METHOD"
    fi

    echo ""
    echo -e "${CYAN}Planned Configuration:${NC}"
    echo -e "  Primary DNS:   ${YELLOW}$PRIMARY_DNS${NC}"
    [[ -n "$SECONDARY_DNS" ]] && echo -e "  Secondary DNS: ${YELLOW}$SECONDARY_DNS${NC}"
    echo -e "  Method:        ${YELLOW}$DNS_METHOD${NC}"
    [[ "$DRY_RUN" == true ]] && echo -e "  Mode:          ${YELLOW}DRY-RUN (no changes will be made)${NC}"
    echo ""

    # Confirmation
    if [[ "$FORCE" != true ]] && [[ "$DRY_RUN" != true ]]; then
        read -r -p "Proceed with DNS configuration? [y/N] " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_info "Aborted by user"
            exit 0
        fi
    fi

    # Create backup directory
    if [[ "$DRY_RUN" != true ]]; then
        mkdir -p "$BACKUP_DIR"
        print_info "Backups will be stored in: $BACKUP_DIR"
    fi

    echo ""

    # Execute configuration based on method
    case "$DNS_METHOD" in
        systemd-resolved)
            configure_systemd_resolved
            ;;
        networkmanager)
            configure_networkmanager
            ;;
        netplan)
            configure_netplan
            ;;
        resolvconf)
            configure_resolvconf
            ;;
        dhclient)
            configure_dhclient
            ;;
        direct)
            configure_direct
            ;;
        *)
            print_error "Unknown DNS method: $DNS_METHOD"
            exit 1
            ;;
    esac

    local config_result=$?

    echo ""

    # Verify configuration
    if [[ "$DRY_RUN" != true ]] && [[ $config_result -eq 0 ]]; then
        verify_dns_config
    fi

    echo ""
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Dry-run complete. No changes were made."
    else
        print_success "DNS configuration complete!"
        echo ""
        echo -e "${CYAN}Backup location:${NC} $BACKUP_DIR"
        echo -e "${CYAN}To restore:${NC} Copy files from backup directory to original locations"
    fi
}

main "$@"
