#!/bin/bash

# Enhanced Comprehensive Firewall Rule Analysis Script for Oracle Linux 9
# Shows firewalld and iptables rules in unified precedence-ordered table
# Includes rich rules, port forwarding, direct rules, ICMP, custom services

# Column width configuration
COL_PRECEDENCE=3
COL_SOURCE=15
COL_ZONE=10
COL_INTERFACE=10
COL_SERVICE=20
COL_PORT=15
COL_ACTION=10
COL_DETAILS=25

# Global variables
declare -a all_rules
declare -i rule_count=0
declare -i conflict_count=0
declare -i rich_rule_count=0
declare -i port_fwd_count=0
declare -i direct_rule_count=0
declare -i icmp_rule_count=0
declare -i custom_service_count=0

# Function to check firewalld status comprehensively
check_firewalld_status() {
    # Get runtime status
    local service_status=$(systemctl is-active firewalld 2>/dev/null)
    
    # Get boot configuration  
    local boot_config=$(systemctl is-enabled firewalld 2>/dev/null)
    
    # Get detailed service state information
    local service_state=$(systemctl show firewalld --property=SubState --value 2>/dev/null)
    
    # Check firewalld internal state
    local firewall_state="unknown"
    if firewall-cmd --state >/dev/null 2>&1; then
        firewall_state="running"
    else
        firewall_state="not running"
    fi
    
    echo "Firewalld runtime status: $service_status"
    echo "Firewalld boot config: $boot_config" 
    echo "Firewalld service state: $service_state"
    echo "Firewalld functional state: $firewall_state"
    echo ""
    
    # Process rules only if service is truly functional
    if [[ "$service_status" == "active" && "$firewall_state" == "running" ]]; then
        return 0
    else
        return 1
    fi
}

# Function to get port from service name using dynamic lookup
get_service_port() {
    local service="$1"
    
    # Get actual firewall service definition
    local ports=$(firewall-cmd --info-service="$service" 2>/dev/null | grep "^[[:space:]]*ports:" | sed 's/^[[:space:]]*ports:[[:space:]]*//')
    
    if [[ -n "$ports" ]]; then
        echo "$ports"
    else
        echo "service lookup failed"
    fi
}

# Function to print table header
print_header() {
    printf "%-${COL_PRECEDENCE}s %-${COL_SOURCE}s %-${COL_ZONE}s %-${COL_INTERFACE}s %-${COL_SERVICE}s %-${COL_PORT}s %-${COL_ACTION}s %s\n" \
           "#" "SOURCE" "ZONE" "INTERFACE" "SERVICE" "PORT" "ACTION" "DETAILS"
    printf "%-${COL_PRECEDENCE}s %-${COL_SOURCE}s %-${COL_ZONE}s %-${COL_INTERFACE}s %-${COL_SERVICE}s %-${COL_PORT}s %-${COL_ACTION}s %s\n" \
           "---" "------" "----" "---------" "-------" "----" "------" "-------"
}

# Function to print rule row
print_rule() {
    local precedence="$1"
    local source="$2"
    local zone="$3"  
    local interface="$4"
    local service="$5"
    local port="$6"
    local action="$7"
    local details="$8"
    
    printf "%-${COL_PRECEDENCE}s %-${COL_SOURCE}s %-${COL_ZONE}s %-${COL_INTERFACE}s %-${COL_SERVICE}s %-${COL_PORT}s %-${COL_ACTION}s %s\n" \
           "$precedence" "$source" "$zone" "$interface" "$service" "$port" "$action" "$details"
}

# Function to parse iptables interface
parse_iptables_interface() {
    local rule="$1"
    
    # Check for input interface (-i)
    if [[ $rule =~ -i[[:space:]]+([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    # Check for output interface (-o)
    elif [[ $rule =~ -o[[:space:]]+([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "ALL"  # No interface specified = all interfaces
    fi
}

# Function to parse iptables port
parse_iptables_port() {
    local rule="$1"
    
    # Look for --dport (destination port)
    if [[ $rule =~ --dport[[:space:]]+([0-9]+) ]]; then
        local port="${BASH_REMATCH[1]}"
        # Determine protocol
        if [[ $rule =~ -p[[:space:]]+tcp ]]; then
            echo "${port}/tcp"
        elif [[ $rule =~ -p[[:space:]]+udp ]]; then
            echo "${port}/udp"
        else
            echo "$port"
        fi

    # Look for dpt: format (from iptables -L output)
    elif [[ $rule =~ dpt:([0-9]+) ]]; then
        local port="${BASH_REMATCH[1]}"
        if [[ $rule =~ tcp ]]; then
            echo "${port}/tcp"
        elif [[ $rule =~ udp ]]; then
            echo "${port}/udp"
        else
            echo "$port"
        fi

    # Look for --sport (source port)
    elif [[ $rule =~ --sport[[:space:]]+([0-9]+) ]]; then
        local port="${BASH_REMATCH[1]}"
        if [[ $rule =~ -p[[:space:]]+tcp ]]; then
            echo "${port}/tcp"
        elif [[ $rule =~ -p[[:space:]]+udp ]]; then
            echo "${port}/udp"
        else
            echo "$port"
        fi

    # Look for spt: format (from iptables -L output)
    elif [[ $rule =~ spt:([0-9]+) ]]; then
        local port="${BASH_REMATCH[1]}"
        if [[ $rule =~ tcp ]]; then
            echo "${port}/tcp"
        elif [[ $rule =~ udp ]]; then
            echo "${port}/udp"
        else
            echo "$port"
        fi
    else
        echo "all"
    fi

}

# Function to parse iptables action
parse_iptables_action() {
    local rule="$1"
    
    if [[ $rule =~ ^[0-9]+[[:space:]]+ACCEPT ]] || [[ $rule =~ -j[[:space:]]+ACCEPT ]]; then
        echo "allow"
    elif [[ $rule =~ ^[0-9]+[[:space:]]+DROP ]] || [[ $rule =~ -j[[:space:]]+DROP ]]; then
        echo "drop"
    elif [[ $rule =~ ^[0-9]+[[:space:]]+REJECT ]] || [[ $rule =~ -j[[:space:]]+REJECT ]]; then
        echo "reject"
    elif [[ $rule =~ -j[[:space:]]+([A-Z_]+) ]]; then
        echo "${BASH_REMATCH[1],,}"  # Convert to lowercase
    else
        echo "unknown"
    fi
}

# Function to get manual iptables rules
get_manual_iptables_rules() {
    # Check if iptables command is available
    if ! command -v iptables >/dev/null 2>&1; then
        echo "iptables command not available - skipping manual iptables rules"
        return
    fi
    
    local precedence=1
    
    # Get iptables rules with line numbers, excluding firewalld chains
    while read -r line_num target prot opt source destination extra; do
        # Skip header lines and firewalld chains
        if [[ "$line_num" =~ ^[0-9]+$ ]] && [[ ! "$target" =~ ^(FWDI|FWDO|FWDX) ]]; then
            # Parse the rule
            local full_rule=$(sudo iptables -L INPUT -n --line-numbers | grep "^$line_num")
            local interface=$(parse_iptables_interface "$full_rule")
            local port=$(parse_iptables_port "$full_rule")
            local action=$(parse_iptables_action "$full_rule")
            
            # Create rule entry
            all_rules+=("$line_num|iptables|-|$interface|-|$port|$action|MANUAL RULE")
            ((rule_count++))
        fi
    done < <(sudo iptables -L INPUT -n --line-numbers 2>/dev/null)
}

# Function to get firewalld rich rules
get_firewalld_rich_rules() {
    local base_precedence=200
    local current_precedence=$base_precedence
    
    # Process each zone for rich rules
    for zone in $(firewall-cmd --get-zones 2>/dev/null); do
        local rich_rules=$(firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null)
        
        if [[ -n "$rich_rules" ]]; then
            while IFS= read -r rich_rule; do
                [[ -z "$rich_rule" ]] && continue
                
                # Parse rich rule for basic information
                local service="-"
                local port="-"
                local action="unknown"
                local src_addr="unknown"
                
                # Extract service if present
                if [[ "$rich_rule" =~ service[[:space:]]+name=\"([^\"]+)\" ]]; then
                    service="${BASH_REMATCH[1]}"
                    port=$(get_service_port "$service")
                else
                    service="all"  # No specific service = all services
                fi
                
                # Extract port if present
                if [[ "$rich_rule" =~ port[[:space:]]+port=\"([^\"]+)\" ]]; then
                    port="${BASH_REMATCH[1]}"
                    if [[ "$rich_rule" =~ protocol=\"([^\"]+)\" ]]; then
                        port="$port/${BASH_REMATCH[1]}"
                    fi
                elif [[ "$service" == "all" ]]; then
                    port="all"  # No specific port and no service = all ports
                fi
                
                # Extract action
                if [[ "$rich_rule" =~ accept ]]; then
                    action="allow"
                elif [[ "$rich_rule" =~ drop ]]; then
                    action="drop"
                elif [[ "$rich_rule" =~ reject ]]; then
                    action="reject"
                fi

                # Extract source address
                if [[ $rich_rule =~ source\ address=\"([^\"]+)\" ]]; then
                    src_addr="src addr: ${BASH_REMATCH[1]}"
                else
                    src_addr="src addr: all"
                fi
                
                # Create rich rule entry
                all_rules+=("$current_precedence|rich-rule|$zone|-|$service|$port|$action|$src_addr")
                ((current_precedence++))
                ((rule_count++))
                ((rich_rule_count++))
            done <<< "$rich_rules"
        fi
    done
}

# Function to get firewalld port forwarding rules
get_firewalld_port_forwarding() {
    local base_precedence=300
    local current_precedence=$base_precedence
    
    # Check for port forwarding in each zone
    for zone in $(firewall-cmd --get-zones 2>/dev/null); do
        # Get forward ports
        local forward_ports=$(firewall-cmd --zone="$zone" --list-forward-ports 2>/dev/null)
        
        if [[ -n "$forward_ports" ]]; then
            while IFS= read -r forward_port; do
                [[ -z "$forward_port" ]] && continue
                
                # Parse forward port rule
                local port="-"
                local to_port="-"
                local to_addr="-"
                
                # Extract port and protocol
                if [[ "$forward_port" =~ port=([0-9]+) ]]; then
                    port="${BASH_REMATCH[1]}"
                fi
                if [[ "$forward_port" =~ proto=([a-zA-Z]+) ]]; then
                    port="$port/${BASH_REMATCH[1]}"
                fi
                if [[ "$forward_port" =~ toport=([0-9]+) ]]; then
                    to_port="${BASH_REMATCH[1]}"
                    port="$port->$to_port"
                fi
                if [[ "$forward_port" =~ toaddr=([0-9.]+) ]]; then
                    to_addr="${BASH_REMATCH[1]}"
                fi
                
                local details="to $to_addr"
                [[ "$to_addr" == "-" ]] && details="local forward"
                
                all_rules+=("$current_precedence|port-fwd|$zone|-|-|$port|forward|$details")
                ((current_precedence++))
                ((rule_count++))
                ((port_fwd_count++))
            done <<< "$forward_ports"
        fi
        
        # Check for masquerading
        if firewall-cmd --zone="$zone" --query-masquerade >/dev/null 2>&1; then
            all_rules+=("$current_precedence|masquerade|$zone|-|-|all|forward|IP masquerading enabled")
            ((current_precedence++))
            ((rule_count++))
            ((port_fwd_count++))
        fi
    done
}

# Function to get firewalld direct rules
get_firewalld_direct_rules() {
    local base_precedence=400
    local current_precedence=$base_precedence
    
    # Get direct rules
    local direct_rules=$(firewall-cmd --direct --get-all-rules 2>/dev/null)
    
    if [[ -n "$direct_rules" ]]; then
        while IFS= read -r direct_rule; do
            [[ -z "$direct_rule" ]] && continue
            
            # Parse direct rule (simplified)
            local table="-"
            local chain="-"
            local action="unknown"
            
            if [[ "$direct_rule" =~ ^([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*) ]]; then
                table="${BASH_REMATCH[1]}"
                chain="${BASH_REMATCH[2]}"
                local rule_part="${BASH_REMATCH[3]}"
                
                if [[ "$rule_part" =~ ACCEPT ]]; then
                    action="allow"
                elif [[ "$rule_part" =~ DROP ]]; then
                    action="drop"
                elif [[ "$rule_part" =~ REJECT ]]; then
                    action="reject"
                fi
            fi
            
            all_rules+=("$current_precedence|direct|-|-|-|all|$action|$table:$chain bypass")
            ((current_precedence++))
            ((rule_count++))
            ((direct_rule_count++))
        done <<< "$direct_rules"
    fi
}

# Function to get firewalld ICMP rules
get_firewalld_icmp_rules() {
    local base_precedence=500
    local current_precedence=$base_precedence
    
    # Process each zone for ICMP settings
    for zone in $(firewall-cmd --get-zones 2>/dev/null); do
        # Check blocked ICMP types
        local blocked_icmp=$(firewall-cmd --zone="$zone" --list-icmp-blocks 2>/dev/null)
        
        if [[ -n "$blocked_icmp" ]]; then
            for icmp_type in $blocked_icmp; do
                all_rules+=("$current_precedence|icmp|$zone|-|$icmp_type|icmp|block|ICMP type blocked")
                ((current_precedence++))
                ((rule_count++))
                ((icmp_rule_count++))
            done
        fi
        
        # Note: By default, ICMP types not explicitly blocked are allowed
        # We could enumerate all possible ICMP types and show allowed ones, but that would be verbose
    done
}

# Function to detect custom services
get_custom_services() {
    local base_precedence=600
    local current_precedence=$base_precedence
    
    # Find custom service files
    if [[ -d /etc/firewalld/services ]]; then
        for service_file in /etc/firewalld/services/*.xml; do
            [[ ! -f "$service_file" ]] && continue
            
            local service_name=$(basename "$service_file" .xml)
            ((custom_service_count++))
            
            # Check if this custom service is actually used in any zone
            local service_used=false
            for zone in $(firewall-cmd --get-zones 2>/dev/null); do
                local zone_services=$(firewall-cmd --zone="$zone" --list-services 2>/dev/null)
                if [[ " $zone_services " =~ " $service_name " ]]; then
                    service_used=true
                    break
                fi
            done
            
            if [[ "$service_used" == true ]]; then
                local custom_ports=$(get_service_port "$service_name")
                all_rules+=("$current_precedence|custom|-|-|$service_name|$custom_ports|allow|custom service in use")
            else
                local custom_ports=$(get_service_port "$service_name")
                all_rules+=("$current_precedence|custom|-|-|$service_name|$custom_ports|unused|custom service defined")
            fi
            ((current_precedence++))
            ((rule_count++))
        done
    fi
}

# Function to get standard firewalld zone rules
get_firewalld_rules() {
    local base_precedence=100  # Start firewalld rules after iptables
    local current_precedence=$base_precedence
    
    # Get default zone for reference
    local default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    
    # Process each zone
    for zone in $(firewall-cmd --get-zones 2>/dev/null); do
        # Get zone information
        local interfaces=$(firewall-cmd --zone="$zone" --list-interfaces 2>/dev/null)
        local services=$(firewall-cmd --zone="$zone" --list-services 2>/dev/null)
        local ports=$(firewall-cmd --zone="$zone" --list-ports 2>/dev/null)
        local sources=$(firewall-cmd --zone="$zone" --list-sources 2>/dev/null)
        
        # Skip empty zones
        if [[ -z "$interfaces" && -z "$services" && -z "$ports" && -z "$sources" ]]; then
            continue
        fi
        
        # Determine if zone is active
        local zone_status="zone service"
        if [[ -z "$interfaces" && -z "$sources" ]]; then
            zone_status="INACTIVE ZONE"
        fi
        
        # Add default zone indicator
        if [[ "$zone" == "$default_zone" ]]; then
            zone_status="$zone_status (DEFAULT)"
        fi
        
        # Set interface list (handle multiple interfaces)
        local interface_list
        if [[ -n "$interfaces" ]]; then
            interface_list="$interfaces"
        elif [[ -n "$sources" ]]; then
            interface_list="-"
            zone_status="source: $(echo $sources | tr ' ' ',')"
        else
            interface_list="-"
        fi
        
        # Process services
        for service in $services; do
            local port=$(get_service_port "$service")
            
            if [[ "$interface_list" == "-" ]]; then
                # Single entry for zone with no interfaces
                all_rules+=("$current_precedence|firewalld|$zone|-|$service|$port|allow|$zone_status")
                ((current_precedence++))
                ((rule_count++))
            else
                # Separate entry for each interface
                for interface in $interface_list; do
                    all_rules+=("$current_precedence|firewalld|$zone|$interface|$service|$port|allow|$zone_status")
                    ((current_precedence++))
                    ((rule_count++))
                done
            fi
        done
        
        # Process custom ports
        for port in $ports; do
            if [[ "$interface_list" == "-" ]]; then
                all_rules+=("$current_precedence|firewalld|$zone|-|-|$port|allow|$zone_status")
                ((current_precedence++))
                ((rule_count++))
            else
                for interface in $interface_list; do
                    all_rules+=("$current_precedence|firewalld|$zone|$interface|-|$port|allow|$zone_status")
                    ((current_precedence++))
                    ((rule_count++))
                done
            fi
        done
    done
}

# Function to detect conflicts
detect_conflicts() {
    local conflicts=0
    
    # Simple conflict detection: look for manual iptables rules that could block firewalld
    declare -A manual_blocks
    declare -A firewalld_allows
    
    # Parse all rules to find conflicts
    for rule in "${all_rules[@]}"; do
        IFS='|' read -r precedence source zone interface service port action details <<< "$rule"
        
        if [[ "$source" == "iptables" && "$action" =~ ^(drop|reject)$ ]]; then
            # Manual rule that blocks
            if [[ "$interface" == "ALL" ]]; then
                manual_blocks["$port"]="ALL"
            else
                manual_blocks["$port:$interface"]="$interface"
            fi
        elif [[ "$source" == "firewalld" && "$action" == "allow" ]]; then
            # firewalld rule that allows
            firewalld_allows["$port:$interface"]="$port"
        fi
    done
    
    # Check for conflicts
    for fw_rule in "${!firewalld_allows[@]}"; do
        IFS=':' read -r port interface <<< "$fw_rule"
        
        # Check if blocked by manual rule
        if [[ -n "${manual_blocks[$port]}" || -n "${manual_blocks[$port:$interface]}" ]]; then
            ((conflicts++))
            
            # Update details to show bypass
            for i in "${!all_rules[@]}"; do
                if [[ "${all_rules[$i]}" =~ firewalld.*$port.*allow ]]; then
                    all_rules[$i]="${all_rules[$i]%|*}|BYPASSED by manual rule"
                fi
            done
        fi
    done
    
    echo $conflicts
}

# Function to print comprehensive footer
print_footer() {
    echo ""
    
    # Default zone
    if systemctl is-active firewalld >/dev/null 2>&1; then
        local default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
        echo "Default firewalld zone: $default_zone"
        
        # Active zones with interfaces
        local active_zones_output=""
        local current_zone=""
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*interfaces: ]]; then
                local interfaces=$(echo "$line" | sed 's/.*interfaces: //')
                if [ -n "$current_zone" ] && [ -n "$interfaces" ]; then
                    if [ -n "$active_zones_output" ]; then
                        active_zones_output="$active_zones_output, "
                    fi
                    active_zones_output="$active_zones_output$current_zone ($interfaces)"
                fi
            elif [[ ! "$line" =~ ^[[:space:]] ]]; then
                current_zone="$line"
            fi
        done < <(firewall-cmd --get-active-zones 2>/dev/null)
        
        echo "Active zones: $active_zones_output"
        
        # Check lockdown mode
        local lockdown_status="unknown"
        if firewall-cmd --query-lockdown >/dev/null 2>&1; then
            lockdown_status="ENABLED"
        else
            lockdown_status="disabled"
        fi
        echo "Lockdown mode: $lockdown_status"
        
    else
        echo "Default firewalld zone: N/A (firewalld not functional)"
        echo "Active zones: N/A (firewalld not functional)"
        echo "Lockdown mode: N/A (firewalld not functional)"
    fi
    
    # Count manual iptables rules
    local manual_count=0
    if command -v iptables >/dev/null 2>&1; then
        manual_count=$(sudo iptables-save 2>/dev/null | grep -v -E "firewalld|FWDI|FWDO|FWDX" | grep -E "^-A" | wc -l)
    fi
    echo "Manual iptables rules detected: $manual_count"
    
    # Rule type counts
    echo "Rich rules detected: $rich_rule_count"
    echo "Port forwarding rules: $port_fwd_count"
    echo "Direct rules detected: $direct_rule_count"
    echo "ICMP rules detected: $icmp_rule_count"
    echo "Custom services detected: $custom_service_count"
    
    # Conflict detection
    echo "Conflicting rules detected: $conflict_count"
    
    # Total rules count
    echo "Total rules displayed: $rule_count"
}

# Main execution
main() {
    echo "Enhanced Firewall Rule Analysis - Oracle Linux 9"
    echo "==============================================="
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script requires root privileges to access firewall rules."
        echo "Please run with sudo: sudo $0"
        exit 1
    fi
    
    # Check firewalld status and decide whether to process firewalld rules
    local process_firewalld=false
    if check_firewalld_status; then
        process_firewalld=true
    fi
    
    # Collect all rules
    get_manual_iptables_rules
    
    if [[ "$process_firewalld" == true ]]; then
        get_firewalld_rules
        get_firewalld_rich_rules
        get_firewalld_port_forwarding
        get_firewalld_direct_rules
        get_firewalld_icmp_rules
        get_custom_services
    else
        echo "Skipping firewalld rule collection due to service status"
        echo ""
    fi
    
    # Sort rules by precedence
    if [[ ${#all_rules[@]} -gt 0 ]]; then
        IFS=$'\n' all_rules=($(sort -t'|' -k1,1n <<< "${all_rules[*]}"))
    fi
    
    # Detect conflicts
    conflict_count=$(detect_conflicts)
    
    # Print table
    print_header
    
    if [[ ${#all_rules[@]} -eq 0 ]]; then
        echo "No firewall rules detected."
    else
        # Print all rules in precedence order
        for rule in "${all_rules[@]}"; do
            IFS='|' read -r precedence source zone interface service port action details <<< "$rule"
            print_rule "$precedence" "$source" "$zone" "$interface" "$service" "$port" "$action" "$details"
        done
    fi
    
    # Print footer
    print_footer
}

# Run main function
main "$@"