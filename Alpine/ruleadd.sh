#!/bin/sh

script_path="/usr/local/bin/ruleadd"

if [ "$0" != "$script_path" ]; then
  cp "$0" "$script_path"
  chmod +x "$script_path"
fi

clear

echo "=== Alpine Linux Iptables Rule Generator ==="
echo ""

echo -n "Enter the primary Destination IP address: "
read dest_ip

echo -n "Do you want to include a second Destination IP? (y/n): "
read add_second

final_dest="$dest_ip"

echo -n "Enter the Source IP address (leave empty for any): "
read source_ip

if [ "$add_second" = "y" ] || [ "$add_second" = "Y" ]; then
    echo -n "Enter the second Destination IP address: "
    read dest_ip2
    if [ -n "$dest_ip2" ]; then
        final_dest="$dest_ip,$dest_ip2"
    else
        echo "Error: Second Destination IP cannot be empty."
        exit 1
    fi
fi

echo -n "Enter port(s) to accept (comma-separated, e.g., 80,443): "
read ports

if [ -z "$ports" ]; then
    echo "Error: You must provide at least one port."
    exit 1
fi

if echo "$ports" | grep -q ","; then
    port_rule="-m multiport --dports $ports"
else
    port_rule="--dport $ports"
fi

if [ -n "$source_ip" ]; then
    src_rule="-s $source_ip"
else
    src_rule=""
fi

iptables_cmd="iptables -A FORWARD -p tcp $src_rule -d $final_dest $port_rule -j ACCEPT"

echo ""
echo "---------------------------------------------------"
echo "Constructed Command:"
echo "$iptables_cmd"
echo "---------------------------------------------------"
echo ""

echo -n "Do you want to apply this rule now? (y/n): "
read confirm

if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    $iptables_cmd
    
    if [ $? -eq 0 ]; then
        echo "Success: Rule applied."
        echo "Don't forget to save your rules (e.g., '/etc/init.d/iptables save')."
    else
        echo "Error: Failed to apply rule. Are you running as root?"
    fi
else
    echo "Operation cancelled."
fi