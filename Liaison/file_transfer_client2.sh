#!/bin/bash

# ==============================================================================
# File: file_transfer_client.sh
# Description: Menu-driven client for connecting to and transferring files with
#              FTP, SFTP, and TFTP servers. Designed to work with servers created
#              by FileTransferServer3.sh. Supports upload/download operations
#              with clear instructions and error handling.
#
# Features:
# - Menu-driven interface for easy navigation
# - Support for FTP, SFTP, and TFTP protocols
# - File upload and download capabilities
# - Interactive sessions for all protocols
# - Server connectivity testing
# - CCDC-optimized with security considerations
# - Cross-platform compatibility (Linux with standard tools)
# - Auto-suggests credentials if /etc/fts_credentials.conf exists (from server script)
#
# Dependencies: ftp, sftp, tftp clients (usually pre-installed)
# Usage: ./file_transfer_client.sh
# Notes:
# - For CCDC: Test connections in safe environment first
# - Ensure server IPs are accessible (check Palo Alto NAT rules)
# - Use strong credentials and monitor transfers
# - If running on same machine as server or copy /etc/fts_credentials.conf, creds auto-suggested
# ==============================================================================

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
 _____ _____ ____ _ _            _   
|  ___|_   _/ ___| (_) ___ _ __ | |_ 
| |_    | || |   | | |/ _ \ '_ \| __|
|  _|   | || |___| | |  __/ | | | |_ 
|_|     |_| \____|_|_|\___|_| |_|\__|
EOF
echo -e "\033[0m"
echo "File Transfer Client - For CCDC Team File Operations"
echo "---------------------------------------------------"

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
CRED_FILE="/etc/fts_credentials.conf"  # Same as server for seamless integration

# --- Global Variables ---
SERVER_IP=""
SERVER_PORT=""
USERNAME=""
PASSWORD=""
PROTOCOL=""
CONNECTION_TESTED=false

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# --- Check Dependencies ---
check_dependencies() {
    local missing_deps=()

    if ! command -v ftp &> /dev/null; then
        missing_deps+=("ftp")
    fi
    if ! command -v sftp &> /dev/null; then
        missing_deps+=("sftp (openssh-client)")
    fi
    if ! command -v tftp &> /dev/null; then
        missing_deps+=("tftp")
    fi
    if ! command -v nc &> /dev/null; then
        missing_deps+=("nc (netcat)")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_warn "Missing dependencies: ${missing_deps[*]}"
        log_info "Install missing clients:"
        echo "  Ubuntu/Debian: sudo apt update && sudo apt install ${missing_deps[*]}"
        echo "  Fedora/RHEL: sudo dnf install ${missing_deps[*]}"
        echo ""
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

recheck_deps_for_protocol() {
    case $PROTOCOL in
        FTP)
            if ! command -v ftp &> /dev/null; then
                log_error "FTP client (ftp) is missing. Please install it."
                return 1
            fi
            ;;
        SFTP)
            if ! command -v sftp &> /dev/null; then
                log_error "SFTP client (sftp) is missing. Please install it."
                return 1
            fi
            ;;
        TFTP)
            if ! command -v tftp &> /dev/null; then
                log_error "TFTP client (tftp) is missing. Please install it."
                return 1
            fi
            ;;
    esac
    return 0
}

# --- Validate IP Address ---
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    return 0
}

# --- Test Server Connectivity ---
test_connectivity() {
    local ip=$1
    local port=$2
    local protocol=$3

    log_info "Testing connectivity to $ip:$port ($protocol)..."

    if nc -z -w3 $ip $port 2>/dev/null; then
        log_info "✅ $protocol server is reachable"
        return 0
    else
        log_error "❌ Cannot reach server at $ip:$port"
        return 1
    fi
}

# --- Get Server Details ---
get_server_details() {
    log_step "Enter Server Connection Details"
    echo ""

    while true; do
        read -p "Server IP Address: " SERVER_IP
        if validate_ip "$SERVER_IP"; then
            break
        else
            log_error "Invalid IP address format. Please try again."
        fi
    done

    case $PROTOCOL in
        ftp|FTP)
            read -p "FTP Port (default 21): " SERVER_PORT
            SERVER_PORT=${SERVER_PORT:-21}
            ;;
        sftp|SFTP)
            read -p "SFTP Port (default 22): " SERVER_PORT
            SERVER_PORT=${SERVER_PORT:-22}
            ;;
        tftp|TFTP)
            read -p "TFTP Port (default 69): " SERVER_PORT
            SERVER_PORT=${SERVER_PORT:-69}
            ;;
    esac

    # Test connectivity
    if test_connectivity "$SERVER_IP" "$SERVER_PORT" "$PROTOCOL"; then
        CONNECTION_TESTED=true
        log_info "Server connection details configured successfully!"
    else
        log_error "Failed to connect to server. Please check IP/port and try again."
    fi
}

# --- Get Authentication Details (with auto-suggest if cred file exists) ---
get_auth_details() {
    log_step "Enter Authentication Details"
    echo ""

    local default_user=""
    local default_pass=""
    local upper_proto=$(echo "$PROTOCOL" | tr '[:lower:]' '[:upper:]')

    # Check for cred file and suggest defaults
    if [ -f "$CRED_FILE" ]; then
        local creds=$(grep "^\[$upper_proto\]" "$CRED_FILE" | cut -d' ' -f2 2>/dev/null)
        if [ -n "$creds" ]; then
            default_user=$(echo "$creds" | cut -d':' -f1)
            default_pass=$(echo "$creds" | cut -d':' -f2)
            log_info "Auto-detected credentials from $CRED_FILE: username=$default_user (you can override)"
        fi
    fi

    case $PROTOCOL in
        ftp|FTP)
            read -p "FTP Username (default: $default_user): " USERNAME
            USERNAME=${USERNAME:-$default_user}
            read -s -p "FTP Password (default: [hidden]): " PASSWORD
            PASSWORD=${PASSWORD:-$default_pass}
            echo ""
            ;;
        sftp|SFTP)
            read -p "SFTP Username (default: $default_user): " USERNAME
            USERNAME=${USERNAME:-$default_user}
            log_info "Note: Password not auto-passed for security reasons."
            log_info "For SFTP, you'll be prompted for password/key during connection (default: [hidden])"
            PASSWORD=$default_pass  # For non-interactive if needed, but sftp prompts
            ;;
        tftp|TFTP)
            log_warn "TFTP doesn't require authentication by default"
            USERNAME=""
            PASSWORD=""
            ;;
    esac
}

# --- Common Interactive Instructions ---
print_interactive_instructions() {
    log_info "Common commands:"
    echo "ls                - List files"
    echo "get <file>        - Download file"
    echo "put <file>        - Upload file"
    echo "mkdir <dir>       - Create directory"
    echo "cd <dir>          - Change directory"
    echo "pwd               - Show current directory"
    echo "help              - Show all commands"
    echo "exit/quit/bye     - Exit session"
    log_info "Use Ctrl+D or 'exit' to return to menu"
}

# --- FTP Operations ---
ftp_operations() {
    log_step "FTP File Transfer Operations"
    echo ""
    log_info "Available operations:"
    echo "1) Upload file to server"
    echo "2) Download file from server"
    echo "3) List server files"
    echo "4) Create directory on server"
    echo "5) Start FTP interactive session"
    echo "6) Return to main menu"
    echo ""

    read -p "Select operation (1-6): " operation

    case $operation in
        1) ftp_upload ;;
        2) ftp_download ;;
        3) ftp_list ;;
        4) ftp_mkdir ;;
        5) ftp_interactive ;;
        6) return ;;
        *) log_error "Invalid option. Please select 1-6." ;;
    esac
}

ftp_upload() {
    log_step "FTP File Upload"
    echo ""

    read -p "Local file path to upload: " local_file
    if [ ! -f "$local_file" ]; then
        log_error "Local file does not exist: $local_file"
        return
    fi

    read -p "Remote directory on server (leave empty for root): " remote_dir
    remote_dir=${remote_dir:-""}

    log_info "Uploading $local_file to server..."

    local temp_output=$(mktemp)
    ( echo "user $USERNAME $PASSWORD"
      if [ -n "$remote_dir" ]; then echo "cd $remote_dir"; fi
      echo "binary"
      echo "put $local_file"
      echo "bye" ) | ftp -n $SERVER_IP $SERVER_PORT > "$temp_output" 2>&1

    if [ $? -eq 0 ]; then
        log_info "✅ File uploaded successfully!"
    else
        log_error "❌ File upload failed. Output: $(cat "$temp_output")"
    fi
    rm -f "$temp_output"
}

ftp_download() {
    log_step "FTP File Download"
    echo ""

    read -p "Remote file path on server: " remote_file
    read -p "Local directory to save (leave empty for current): " local_dir
    local_dir=${local_dir:-"."}

    if [ ! -d "$local_dir" ]; then
        mkdir -p "$local_dir"
    fi

    log_info "Downloading $remote_file to $local_dir..."

    local temp_output=$(mktemp)
    local remote_basename=$(basename "$remote_file")
    ( echo "user $USERNAME $PASSWORD"
      echo "binary"
      echo "get $remote_file $local_dir/$remote_basename"
      echo "bye" ) | ftp -n $SERVER_IP $SERVER_PORT > "$temp_output" 2>&1

    if [ $? -eq 0 ]; then
        log_info "✅ File downloaded successfully!"
    else
        log_error "❌ File download failed. Output: $(cat "$temp_output")"
    fi
    rm -f "$temp_output"
}

ftp_list() {
    log_step "FTP List Files"
    echo ""

    read -p "Remote directory (leave empty for root): " remote_dir
    remote_dir=${remote_dir:-""}

    log_info "Listing files in $remote_dir..."

    ( echo "user $USERNAME $PASSWORD"
      if [ -n "$remote_dir" ]; then echo "cd $remote_dir"; fi
      echo "ls"
      echo "bye" ) | ftp -n $SERVER_IP $SERVER_PORT
}

ftp_mkdir() {
    log_step "FTP Create Directory"
    echo ""

    read -p "Remote directory name to create: " remote_dir

    log_info "Creating directory $remote_dir..."

    local temp_output=$(mktemp)
    ( echo "user $USERNAME $PASSWORD"
      echo "mkdir $remote_dir"
      echo "bye" ) | ftp -n $SERVER_IP $SERVER_PORT > "$temp_output" 2>&1

    if [ $? -eq 0 ]; then
        log_info "✅ Directory created successfully!"
    else
        log_error "❌ Directory creation failed. Output: $(cat "$temp_output")"
    fi
    rm -f "$temp_output"
}

ftp_interactive() {
    log_step "FTP Interactive Session"
    print_interactive_instructions
    log_info "Connecting to FTP server... (You will be prompted for commands)"

    ftp -n $SERVER_IP $SERVER_PORT <<EOF
user $USERNAME $PASSWORD
EOF
    # ftp will enter interactive mode after login
}

# --- SFTP Operations ---
sftp_operations() {
    log_step "SFTP File Transfer Operations"
    echo ""
    log_info "Available operations:"
    echo "1) Start SFTP interactive session"
    echo "2) Return to main menu"
    echo ""

    read -p "Select operation (1-2): " operation

    case $operation in
        1) sftp_interactive ;;
        2) return ;;
        *) log_error "Invalid option. Please select 1-2." ;;
    esac
}

sftp_interactive() {
    log_step "SFTP Interactive Session"
    print_interactive_instructions
    log_info "Connecting to SFTP server... (You will be prompted for password/key)"

    sftp -P $SERVER_PORT $USERNAME@$SERVER_IP || log_error "❌ SFTP connection failed. Check credentials, port, and server status."
}

# --- TFTP Operations ---
tftp_operations() {
    log_step "TFTP File Transfer Operations"
    echo ""
    log_info "Available operations:"
    echo "1) Upload file to server"
    echo "2) Download file from server"
    echo "3) Start TFTP interactive session"
    echo "4) Return to main menu"
    echo ""

    read -p "Select operation (1-4): " operation

    case $operation in
        1) tftp_upload ;;
        2) tftp_download ;;
        3) tftp_interactive ;;
        4) return ;;
        *) log_error "Invalid option. Please select 1-4." ;;
    esac
}

tftp_upload() {
    log_step "TFTP File Upload"
    echo ""

    read -p "Local file path to upload: " local_file
    if [ ! -f "$local_file" ]; then
        log_error "Local file does not exist: $local_file"
        return
    fi

    read -p "Remote filename on server: " remote_file

    log_info "Uploading $local_file as $remote_file..."

    # Create TFTP script
    local tftp_script=$(mktemp)
    cat > "$tftp_script" << EOF
verbose
connect $SERVER_IP $SERVER_PORT
mode binary
put "$local_file" "$remote_file"
quit
EOF

    local output=$(tftp < "$tftp_script" 2>&1)

    if [ $? -eq 0 ]; then
        log_info "✅ File uploaded successfully!"
    else
        log_error "❌ File upload failed. Output: $output"
    fi

    rm -f "$tftp_script"
}

tftp_download() {
    log_step "TFTP File Download"
    echo ""

    read -p "Remote filename on server: " remote_file
    read -p "Local directory to save file (leave empty for current): " local_dir
    local_dir=${local_dir:-"."}

    if [ ! -d "$local_dir" ]; then
        mkdir -p "$local_dir"
    fi

    log_info "Downloading $remote_file to $local_dir..."

    # Create TFTP script
    local tftp_script=$(mktemp)
    cat > "$tftp_script" << EOF
verbose
connect $SERVER_IP $SERVER_PORT
mode binary
get "$remote_file" "$local_dir/$(basename "$remote_file")"
quit
EOF

    local output=$(tftp < "$tftp_script" 2>&1)

    if [ $? -eq 0 ]; then
        log_info "✅ File downloaded successfully!"
    else
        log_error "❌ File download failed. Output: $output"
    fi

    rm -f "$tftp_script"
}

tftp_interactive() {
    log_step "TFTP Interactive Session"
    print_interactive_instructions
    log_info "Connecting to TFTP server... (Note: TFTP has limited commands; no auth required)"

    tftp $SERVER_IP $SERVER_PORT || log_error "❌ TFTP connection failed. Check port and server status."
}

# --- Main Menu ---
show_main_menu() {
    echo ""
    log_info "File Transfer Client Main Menu"
    echo "==============================="
    echo "1) Connect to FTP Server"
    echo "2) Connect to SFTP Server"
    echo "3) Connect to TFTP Server"
    echo "4) Test Server Connectivity"
    echo "5) Show Connection Status"
    echo "6) Exit"
    echo ""
}

# --- FTP Menu ---
show_ftp_menu() {
    echo ""
    log_info "FTP Operations Menu"
    echo "===================="
    echo "Server: $SERVER_IP:$SERVER_PORT"
    echo "User: $USERNAME"
    echo ""
    echo "1) Upload file to server"
    echo "2) Download file from server"
    echo "3) List server files"
    echo "4) Create directory on server"
    echo "5) Start FTP interactive session"
    echo "6) Change server connection"
    echo "7) Return to main menu"
    echo ""
}

# --- SFTP Menu ---
show_sftp_menu() {
    echo ""
    log_info "SFTP Operations Menu"
    echo "====================="
    echo "Server: $SERVER_IP:$SERVER_PORT"
    echo "User: $USERNAME"
    echo ""
    echo "1) Start SFTP interactive session"
    echo "2) Change server connection"
    echo "3) Return to main menu"
    echo ""
}

# --- TFTP Menu ---
show_tftp_menu() {
    echo ""
    log_info "TFTP Operations Menu"
    echo "====================="
    echo "Server: $SERVER_IP:$SERVER_PORT"
    echo ""
    echo "1) Upload file to server"
    echo "2) Download file from server"
    echo "3) Start TFTP interactive session"
    echo "4) Change server connection"
    echo "5) Return to main menu"
    echo ""
}

# --- Handle FTP Connection ---
handle_ftp_connection() {
    if ! recheck_deps_for_protocol; then
        return
    fi
    if [ "$CONNECTION_TESTED" = false ]; then
        get_server_details
        get_auth_details
    fi

    while true; do
        show_ftp_menu
        read -p "Select option (1-7): " choice

        case $choice in
            1|2|3|4|5) ftp_operations ;;
            6)
                CONNECTION_TESTED=false
                get_server_details
                get_auth_details
                ;;
            7) return ;;
            *) log_error "Invalid option. Please select 1-7." ;;
        esac
    done
}

# --- Handle SFTP Connection ---
handle_sftp_connection() {
    if ! recheck_deps_for_protocol; then
        return
    fi
    if [ "$CONNECTION_TESTED" = false ]; then
        get_server_details
        get_auth_details
    fi

    while true; do
        show_sftp_menu
        read -p "Select option (1-3): " choice

        case $choice in
            1) sftp_operations ;;
            2)
                CONNECTION_TESTED=false
                get_server_details
                get_auth_details
                ;;
            3) return ;;
            *) log_error "Invalid option. Please select 1-3." ;;
        esac
    done
}

# --- Handle TFTP Connection ---
handle_tftp_connection() {
    if ! recheck_deps_for_protocol; then
        return
    fi
    if [ "$CONNECTION_TESTED" = false ]; then
        get_server_details
    fi

    while true; do
        show_tftp_menu
        read -p "Select option (1-5): " choice

        case $choice in
            1|2|3) tftp_operations ;;
            4)
                CONNECTION_TESTED=false
                get_server_details
                ;;
            5) return ;;
            *) log_error "Invalid option. Please select 1-5." ;;
        esac
    done
}

# --- Test Connectivity ---
test_server_connection() {
    log_step "Test Server Connectivity"
    echo ""

    read -p "Server IP Address: " test_ip
    if ! validate_ip "$test_ip"; then
        log_error "Invalid IP address format"
        return
    fi

    log_info "Testing FTP (port 21)..."
    test_connectivity "$test_ip" "21" "FTP" || true

    log_info "Testing SFTP (port 22)..."
    test_connectivity "$test_ip" "22" "SFTP" || true

    log_info "Testing TFTP (port 69)..."
    test_connectivity "$test_ip" "69" "TFTP" || true

    log_info "Connectivity test complete!"
}

# --- Show Connection Status ---
show_connection_status() {
    log_step "Current Connection Status"
    echo ""

    if [ "$CONNECTION_TESTED" = true ]; then
        log_info "✅ Connected to $PROTOCOL server: $SERVER_IP:$SERVER_PORT"
        if [ -n "$USERNAME" ]; then
            log_info "User: $USERNAME"
        fi
    else
        log_warn "❌ No active server connection"
        log_info "Use options 1-3 to connect to a server"
    fi
}

# --- Main Function ---
main() {
    check_dependencies

    log_info "Welcome to the File Transfer Client!"
    log_info "This tool helps you connect to and transfer files with FTP/SFTP/TFTP servers."
    echo ""

    while true; do
        show_main_menu
        read -p "Select option (1-6): " choice

        case $choice in
            1)
                PROTOCOL="FTP"
                PROTOCOL=$(echo "$PROTOCOL" | tr '[:lower:]' '[:upper:]')
                handle_ftp_connection
                ;;
            2)
                PROTOCOL="SFTP"
                PROTOCOL=$(echo "$PROTOCOL" | tr '[:lower:]' '[:upper:]')
                handle_sftp_connection
                ;;
            3)
                PROTOCOL="TFTP"
                PROTOCOL=$(echo "$PROTOCOL" | tr '[:lower:]' '[:upper:]')
                handle_tftp_connection
                ;;
            4)
                test_server_connection
                ;;
            5)
                show_connection_status
                ;;
            6)
                log_info "Thank you for using File Transfer Client!"
                log_info "Remember to secure your file transfers in CCDC environments."
                exit 0
                ;;
            *)
                log_error "Invalid option. Please select 1-6."
                ;;
        esac
    done
}

# --- Run Main Function ---
main "$@"