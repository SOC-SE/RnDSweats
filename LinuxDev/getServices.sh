#!/bin/bash

# Three-section service status script
# Shows Active, Inactive, and Malformed services in clean 50-10-10 format

# Arrays to store services by category
declare -a active_services
declare -a inactive_services  
declare -a malformed_services

# Read systemctl output and categorize services
while read -r unit load active sub description; do
    # Skip empty lines
    [[ -z "$unit" ]] && continue
    
    # Handle malformed services with ● character (different field order)
    if [[ "$unit" == *"●"* ]]; then
        # For ● entries: ● service.name not-found inactive dead service.name
        service_name=${load%.service}  # load field contains the actual service name
        load_state="$active"           # active field contains the load state
        active_state="$sub"            # sub field contains the active state
        malformed_services+=("$service_name|$active_state|$load_state")
    else
        # Normal services: service.name loaded active sub description
        service_name=${unit%.service}
        
        if [[ "$load" == "not-found" ]]; then
            # Malformed services without ● character
            malformed_services+=("$service_name|$active|$load")
        elif [[ "$active" == "active" ]]; then
            # Active services
            active_services+=("$service_name|$active|$sub")
        else
            # Inactive services (loaded but not active)
            inactive_services+=("$service_name|$active|$sub")
        fi
    fi
done < <(systemctl list-units --type=service --no-pager --no-legend --all)

# Function to print section header
print_header() {
    local title="$1"
    local col3_name="$2"
    
    echo
    echo "=== $title ==="
    printf "%-50s %-10s %-15s\n" "SERVICE" "STATUS" "$col3_name"
    printf "%-50s %-10s %-15s\n" "$(printf '%*s' 50 | tr ' ' '-')" "$(printf '%*s' 10 | tr ' ' '-')" "$(printf '%*s' 15 | tr ' ' '-')"
}

# Function to get state priority for sorting (lower number = higher priority)
get_state_priority() {
    local state="$1"
    case "$state" in
        "degraded")         echo "1" ;;
        "failed")           echo "2" ;;
        "error")            echo "3" ;;
        "activating")       echo "4" ;;
        "deactivating")     echo "5" ;;
        "reloading")        echo "6" ;;
        "running")          echo "7" ;;
        "exited")           echo "8" ;;
        *)                  echo "9" ;;  # Any other states
    esac
}

# Function to sort active services by state priority, then by name
sort_active_services() {
    local -n services_array=$1
    local temp_file=$(mktemp)
    
    # Create sortable entries with priority prefix
    for service_entry in "${services_array[@]}"; do
        IFS='|' read -r name status state <<< "$service_entry"
        priority=$(get_state_priority "$state")
        echo "${priority}|${name}|${service_entry}" >> "$temp_file"
    done
    
    # Sort by priority then by name, then extract original entries
    services_array=()
    while IFS='|' read -r priority name original_entry; do
        services_array+=("$original_entry")
    done < <(sort -t'|' -k1,1n -k2,2 "$temp_file")
    
    rm "$temp_file"
}

# Function to sort services alphabetically by name
sort_services_alphabetically() {
    local -n services_array=$1
    local temp_file=$(mktemp)
    
    # Create sortable entries
    for service_entry in "${services_array[@]}"; do
        IFS='|' read -r name status state <<< "$service_entry"
        echo "${name}|${service_entry}" >> "$temp_file"
    done
    
    # Sort by name, then extract original entries
    services_array=()
    while IFS='|' read -r name original_entry; do
        services_array+=("$original_entry")
    done < <(sort -t'|' -k1,1 "$temp_file")
    
    rm "$temp_file"
}

# Function to print services from array
print_services() {
    local -n services_array=$1
    
    for service_entry in "${services_array[@]}"; do
        IFS='|' read -r name status state <<< "$service_entry"
        printf "%-50s %-10s %-15s\n" "$name" "$status" "$state"
    done
}

# Print Active Services section
print_header "Active Services" "STATE"
if [[ ${#active_services[@]} -eq 0 ]]; then
    echo "No active services found."
else
    sort_active_services active_services
    print_services active_services
fi

# Print Inactive Services section  
print_header "Inactive Services" "STATE"
if [[ ${#inactive_services[@]} -eq 0 ]]; then
    echo "No inactive services found."
else
    sort_services_alphabetically inactive_services
    print_services inactive_services
fi

# Print Malformed Services section
print_header "Malformed Services" "LOAD-STATE"
if [[ ${#malformed_services[@]} -eq 0 ]]; then
    echo "No malformed services found."
else
    sort_services_alphabetically malformed_services
    print_services malformed_services
fi

echo
echo "Summary:"
echo "  Active services: ${#active_services[@]}"
echo "  Inactive services: ${#inactive_services[@]}"
echo "  Malformed services: ${#malformed_services[@]}"