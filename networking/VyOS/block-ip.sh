#!/bin/sh

if [ -z "$1" ]; then
  echo "Usage: $0 <IP_ADDRESS>"
  exit 1
fi

script_path="/usr/local/bin/block-ip"

if [ "$0" != "$script_path" ]; then
  cp "$0" "$script_path"
  chmod +x "$script_path"
fi

ip_addr="$1"

iptables -I 1 INPUT -s "$ip_addr" -j DROP
iptables -I 1 FORWARD -s "$ip_addr" -j DROP
iptables -I 1 OUTPUT -s "$ip_addr" -j DROP

echo "Traffic from $ip_addr is now being dropped."