#!/bin/sh

script_path="/usr/local/bin/ruledel"

if [ "$0" != "$script_path" ]; then
  cp "$0" "$script_path"
  chmod +x "$script_path"
fi


if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

echo "=== Select an iptables Table ==="
echo "1) filter"
echo "2) nat"
echo "3) mangle"
echo "4) raw"
echo "5) security"

printf "Enter the number of the table: "
read -r choice

case "$choice" in
    1) TABLE="filter" ;;
    2) TABLE="nat" ;;
    3) TABLE="mangle" ;;
    4) TABLE="raw" ;;
    5) TABLE="security" ;;
    *) echo "Invalid selection. Exiting."; exit 1 ;;
esac

echo ""
echo "Selected Table: $TABLE"
echo "---"

echo "=== Available Chains in '$TABLE' ==="
chains=$(iptables -t "$TABLE" -L -n | grep "^Chain" | awk '{print $2}')

if [ -z "$chains" ]; then
    echo "No chains found (or error accessing table). Exiting."
    exit 1
fi

i=1
for chain in $chains; do
    echo "$i) $chain"
    eval "CHAIN_$i='$chain'"
    i=$((i + 1))
done

chain_count=$((i - 1))

printf "Enter the number of the chain: "
read -r chain_choice

if ! echo "$chain_choice" | grep -qE '^[0-9]+$' || [ "$chain_choice" -lt 1 ] || [ "$chain_choice" -gt "$chain_count" ]; then
    echo "Invalid chain selection. Exiting."
    exit 1
fi

eval "CHAIN=\$CHAIN_$chain_choice"

echo ""
echo "Selected Chain: $CHAIN"
echo "---"

echo "=== Rules in $CHAIN (Table: $TABLE) ==="
rule_check=$(iptables -t "$TABLE" -L "$CHAIN" --line-numbers -n | tail -n +3)

if [ -z "$rule_check" ]; then
    echo "No rules found in this chain."
    exit 0
fi

iptables -t "$TABLE" -L "$CHAIN" --line-numbers -n

echo ""
echo "Warning: Deleting a rule is immediate."

printf "Enter the Line Number to DELETE (or 'q' to quit): "
read -r rule_num

if [ "$rule_num" = "q" ]; then
    echo "Operation cancelled."
    exit 0
fi

if ! echo "$rule_num" | grep -qE '^[0-9]+$'; then
    echo "Error: Input must be a valid integer."
    exit 1
fi

echo "Attempting to delete rule $rule_num from $CHAIN..."
if iptables -t "$TABLE" -D "$CHAIN" "$rule_num"; then
    echo "Success: Rule $rule_num deleted from $CHAIN."
else
    echo "Error: Failed to delete rule. Please check if the line number exists."
fi