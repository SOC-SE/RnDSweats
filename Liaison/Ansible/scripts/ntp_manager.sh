#!/bin/bash
# =============================================================================
# NTP Manager - Interactive Hub-and-Spoke Configuration Tool
# =============================================================================
# Manages NTP Master/Client roles for CCDC Ansible deployment
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Paths (relative to repo root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
INVENTORY="$REPO_ROOT/inventory/inventory.ini"
GROUP_VARS="$REPO_ROOT/group_vars/all.yml"

# =============================================================================
# FUNCTIONS
# =============================================================================

show_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}          ${GREEN}NTP Hub-and-Spoke Manager${NC}                           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          ${YELLOW}MWCCDC Ansible Toolkit${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_current_config() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}CURRENT NTP CONFIGURATION${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Get current master
    CURRENT_MASTER=$(grep -A1 '^\[ntp_servers\]' "$INVENTORY" | tail -1 | awk '{print $1}')
    CURRENT_MASTER_IP=$(grep -A1 '^\[ntp_servers\]' "$INVENTORY" | tail -1 | grep -oP 'ansible_host=\K[0-9.]+')
    
    echo -e "${YELLOW}Master Server (Stratum 10 Orphan):${NC}"
    echo -e "  → ${GREEN}$CURRENT_MASTER${NC} ($CURRENT_MASTER_IP)"
    echo ""
    
    echo -e "${YELLOW}Client Machines:${NC}"
    # Extract clients (lines between [ntp_clients] and next section or EOF)
    awk '/^\[ntp_clients\]/,/^\[/' "$INVENTORY" | grep -v '^\[' | grep -v '^#' | grep -v '^$' | while read -r line; do
        HOST=$(echo "$line" | awk '{print $1}')
        IP=$(echo "$line" | grep -oP 'ansible_host=\K[0-9.]+')
        if [ -n "$HOST" ]; then
            echo -e "  → ${CYAN}$HOST${NC} ($IP)"
        fi
    done
    echo ""
    
    # Show master IP from group_vars
    MASTER_IP_VAR=$(grep 'ntp_master_ip:' "$GROUP_VARS" | awk '{print $2}')
    echo -e "${YELLOW}Master IP in group_vars:${NC} $MASTER_IP_VAR"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

list_available_hosts() {
    echo -e "${YELLOW}Available Linux Hosts:${NC}"
    echo ""
    
    # Get all hosts from [linux_servers]
    i=1
    declare -g -a HOST_LIST=()
    declare -g -a IP_LIST=()
    
    awk '/^\[linux_servers\]/,/^\[/' "$INVENTORY" | grep -v '^\[' | grep -v '^#' | grep -v '^$' | while read -r line; do
        HOST=$(echo "$line" | awk '{print $1}')
        IP=$(echo "$line" | grep -oP 'ansible_host=\K[0-9.]+')
        if [ -n "$HOST" ]; then
            echo "  $i) $HOST ($IP)"
            ((i++))
        fi
    done
}

change_master() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}CHANGE NTP MASTER${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Get all linux servers into arrays
    mapfile -t HOSTS < <(awk '/^\[linux_servers\]/,/^\[/' "$INVENTORY" | grep -v '^\[' | grep -v '^#' | grep -v '^$' | awk '{print $1}')
    mapfile -t IPS < <(awk '/^\[linux_servers\]/,/^\[/' "$INVENTORY" | grep -v '^\[' | grep -v '^#' | grep -v '^$' | grep -oP 'ansible_host=\K[0-9.]+')
    
    # Display menu
    echo -e "${YELLOW}Select new NTP Master:${NC}"
    for i in "${!HOSTS[@]}"; do
        echo "  $((i+1))) ${HOSTS[$i]} (${IPS[$i]})"
    done
    echo ""
    
    read -p "Enter number (1-${#HOSTS[@]}): " choice
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#HOSTS[@]}" ]; then
        echo -e "${RED}Invalid selection.${NC}"
        return 1
    fi
    
    NEW_MASTER="${HOSTS[$((choice-1))]}"
    NEW_MASTER_IP="${IPS[$((choice-1))]}"
    
    echo ""
    echo -e "${YELLOW}Updating configuration...${NC}"
    
    # Build new ntp_servers section
    NEW_NTP_SERVERS="[ntp_servers]\n$NEW_MASTER     ansible_host=$NEW_MASTER_IP   # NTP MASTER (Stratum 10)"
    
    # Build new ntp_clients section (all hosts except the new master)
    NEW_NTP_CLIENTS="[ntp_clients]"
    for i in "${!HOSTS[@]}"; do
        if [ "${HOSTS[$i]}" != "$NEW_MASTER" ]; then
            NEW_NTP_CLIENTS="$NEW_NTP_CLIENTS\n${HOSTS[$i]}  ansible_host=${IPS[$i]}   # NTP Client"
        fi
    done
    
    # Update inventory.ini using sed
    # Replace [ntp_servers] section
    sed -i "/^\[ntp_servers\]/,/^$/c\\$NEW_NTP_SERVERS\n" "$INVENTORY"
    
    # Replace [ntp_clients] section  
    sed -i "/^\[ntp_clients\]/,/^\[/{ /^\[ntp_clients\]/,/^[^#]/c\\$NEW_NTP_CLIENTS\n}" "$INVENTORY"
    
    # Update group_vars/all.yml - replace ntp_master_ip line
    sed -i "s/^ntp_master_ip:.*/ntp_master_ip: $NEW_MASTER_IP       # $NEW_MASTER (NTP Master)/" "$GROUP_VARS"
    
    echo -e "${GREEN}✓ Updated inventory.ini${NC}"
    echo -e "${GREEN}✓ Updated group_vars/all.yml${NC}"
    echo ""
    echo -e "${CYAN}New Master: $NEW_MASTER ($NEW_MASTER_IP)${NC}"
    echo ""
    
    read -p "Deploy NTP now? (y/N): " deploy
    if [[ "$deploy" =~ ^[Yy]$ ]]; then
        deploy_ntp
    fi
}

deploy_ntp() {
    echo ""
    echo -e "${YELLOW}Deploying NTP configuration...${NC}"
    echo ""
    cd "$REPO_ROOT"
    ansible-playbook playbooks/liaison_main.yml -e tool=ntp -K
}

show_runtime_override() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}RUNTIME OVERRIDE (No File Changes)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}Temporarily override Master without modifying files:${NC}"
    echo ""
    echo -e "# Make Splunk the Master (one-time, no persistence)"
    echo -e "${CYAN}ansible-playbook playbooks/liaison_main.yml -e tool=ntp \\${NC}"
    echo -e "${CYAN}  -e ntp_master_ip=172.20.242.20 \\${NC}"
    echo -e "${CYAN}  --limit splunk,fedora_webmail,ubuntu_ecom -K${NC}"
    echo ""
    echo -e "# Make Fedora the Master"
    echo -e "${CYAN}ansible-playbook playbooks/liaison_main.yml -e tool=ntp \\${NC}"
    echo -e "${CYAN}  -e ntp_master_ip=172.20.242.101 \\${NC}"
    echo -e "${CYAN}  --limit splunk,fedora_webmail,ubuntu_ecom -K${NC}"
    echo ""
    echo -e "${YELLOW}Note:${NC} This does NOT update inventory.ini or group_vars. Changes"
    echo -e "      apply only for this run. Use Option 2 for persistent changes."
    echo ""
}

# =============================================================================
# MAIN MENU
# =============================================================================

main_menu() {
    while true; do
        show_header
        show_current_config
        
        echo -e "${YELLOW}Options:${NC}"
        echo "  1) Show current NTP configuration"
        echo "  2) Change NTP Master (updates files)"
        echo "  3) Deploy NTP (run playbook)"
        echo "  4) Show runtime override commands"
        echo "  5) Exit"
        echo ""
        read -p "Select option (1-5): " option
        
        case $option in
            1)
                show_header
                show_current_config
                read -p "Press Enter to continue..."
                ;;
            2)
                show_header
                change_master
                read -p "Press Enter to continue..."
                ;;
            3)
                deploy_ntp
                read -p "Press Enter to continue..."
                ;;
            4)
                show_header
                show_runtime_override
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
# ENTRY POINT
# =============================================================================

# Check if inventory exists
if [ ! -f "$INVENTORY" ]; then
    echo -e "${RED}Error: Inventory file not found at $INVENTORY${NC}"
    exit 1
fi

if [ ! -f "$GROUP_VARS" ]; then
    echo -e "${RED}Error: group_vars/all.yml not found at $GROUP_VARS${NC}"
    exit 1
fi

main_menu
