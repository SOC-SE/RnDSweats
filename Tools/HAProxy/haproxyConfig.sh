#!/bin/bash

set -e

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Function to Print Messages ---
log_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

get_proxies() {
    grep '^#s' /etc/haproxy/haproxy.cfg | sed 's/^#s//; s/-proxy$//' || true
}

# --- Root User Check ---
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root. Please use sudo."
  exit 1
fi

echo -e '
 __    __   ______                     __   __                             ______   __
/  |  /  | /      \                   /  | /  |                           /      \ /  |
$$ |  $$ |/$$$$$$  |  ______    ______    ______ $$ |  $$ | __    __         _______   ______    _______  /$$$$$$  |$$/   ______
$$ |__$$ |$$ |__$$ | /      \  /      \  /      \$$  \/$$/ /  |  /  |        /       | /      \ /       \ $$ |_ $$/ /  | /      \
$$    $$ |$$    $$ |/$$$$$$  |/$$$$$$  |/$$$$$$  |$$  $$<  $$ |  $$ |       /$$$$$$$/ /$$$$$$  |$$$$$$$  |$$    |   $$ |/$$$$$$  |
$$$$$$$$ |$$$$$$$$ |$$ |  $$ |$$ |  $$/ $$ |  $$ | $$$$  \ $$ |  $$ |       $$ |      $$ |  $$ |$$ |  $$ |$$$$/     $$ |$$ |  $$ |
$$ |  $$ |$$ |  $$ |$$ |__$$ |$$ |      $$ \__$$ |$$ /$$  |$$ \__$$ |       $$ \_____ $$ \__$$ |$$ |  $$ |$$ |      $$ |$$ \__$$ |
$$ |  $$ |$$ |  $$ |$$    $$/ $$ |      $$    $$/$$ |  $$ |$$    $$ |       $$        |$$    $$/ $$ |  $$ |$$ |      $$ |$$    $$ |
$$/   $$/ $$/   $$/ $$$$$$$/  $$/        $$$$$$/ $$/   $$/  $$$$$$$ |        $$$$$$$/  $$$$$$/  $$/   $$/ $$/       $$/  $$$$$$$ |
                                                     /  \__$$ |                                             /  \__$$ |
                                                     $$    $$/                                              $$    $$/
                                                      $$$$$$/                                                $$$$$$/
'


read -p "\n\nSelect an operation (1: Add, 2: List, 3: Remove, 4: Print Config): " response

case $response in
  1) # Add
    read -p "Enter a name for the proxy entry: " p_name
    read -p "Enter the incoming port number for the proxy server: " p_port
    read -p "Enter the backend IP: " b_ip
    read -p "Enter the backend port: " b_port

    sed -i "$ a\\\n#s${p_name}-proxy\nfrontend f-${p_name}\n  bind 127.0.0.1:${p_port}\n  default_backend b-${p_name}\n\nbackend b-${p_name}\n  server server1 ${b_ip}:${b_port}\n#e${p_name}-proxy" /etc/haproxy/haproxy.cfg

    read -p "HTTP or TCP protocol? (h/t) [h]: " ht
    if [ "$ht" = 't' ]; then
      sed -i "/frontend f-${p_name}/a \  mode tcp" /etc/haproxy/haproxy.cfg
    fi
    log_message "Proxy '${p_name}' added successfully."
    ;;

  2) # List
    log_message "Currently configured proxies:"
    get_proxies
    ;;

  3) # Remove
    echo "Available proxies to remove:"
    get_proxies
    echo ""

    read -p "Enter the name of the proxy block to remove: " p_name

    if ! get_proxies | grep -q "^${p_name}$"; then
        log_warning "Proxy '${p_name}' not found."
        exit 1
    fi

    sed -i "/^#s${p_name}-proxy$/,/^#e${p_name}-proxy$/d" /etc/haproxy/haproxy.cfg
    log_message "Proxy '${p_name}' has been removed."
    ;;

  4) # Print Config
    cat /etc/haproxy/haproxy.cfg | awk "/#s/,0"
  *)
    log_warning "Invalid option selected."
    exit 1
    ;;
esac
