#!/bin/bash

# ==============================================================================
# Script Name: install_technitium_fixed.sh
# Description: Installs Technitium DNS Server with improved error handling
# Author: Enhanced version
# ==============================================================================

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration Variables
INSTALL_DIR="/opt/technitium-dns"
WEB_PORT="5380"
CONTAINER_NAME="technitium-dns"

# ==============================================================================
# Functions
# ==============================================================================

print_header() {
    echo -e "\n${BLUE}================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root (sudo)"
        exit 1
    fi
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        echo "Install with: curl -fsSL https://get.docker.com | sh"
        exit 1
    fi
    
    if ! systemctl is-active --quiet docker; then
        print_warning "Docker service is not running. Starting..."
        systemctl start docker
        systemctl enable docker
    fi
    
    print_success "Docker is installed and running"
}

# Handle systemd-resolved conflict on port 53
handle_port53_conflict() {
    print_info "Checking for port 53 conflicts..."
    
    if ss -tuln | grep -q ":53 "; then
        print_warning "Port 53 is in use (likely systemd-resolved)"
        
        echo -e "\n${YELLOW}Options:${NC}"
        echo "  1) Disable systemd-resolved stub listener (recommended)"
        echo "  2) Continue anyway (may fail)"
        echo "  3) Exit and fix manually"
        
        read -p "Choose option [1-3]: " choice
        
        case $choice in
            1)
                print_info "Disabling systemd-resolved stub listener..."
                
                # Backup original config
                if [ -f /etc/systemd/resolved.conf ]; then
                    cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup
                    print_success "Backed up original config"
                fi
                
                # Disable DNSStubListener
                sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
                sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
                
                # Restart systemd-resolved
                systemctl restart systemd-resolved
                
                # Verify port is free
                sleep 2
                if ss -tuln | grep -q ":53 "; then
                    print_error "Port 53 is still in use. Manual intervention required."
                    print_info "Run: sudo lsof -i :53"
                    exit 1
                fi
                
                print_success "Port 53 is now available"
                ;;
            2)
                print_warning "Continuing with port conflict - container may fail to start"
                ;;
            3)
                print_info "Exiting. To fix manually:"
                echo "  sudo sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf"
                echo "  sudo systemctl restart systemd-resolved"
                exit 0
                ;;
            *)
                print_error "Invalid option"
                exit 1
                ;;
        esac
    else
        print_success "Port 53 is available"
    fi
}

# Create directory structure
create_directories() {
    print_info "Creating directory structure at ${INSTALL_DIR}..."
    
    mkdir -p "$INSTALL_DIR/config"
    chmod 755 "$INSTALL_DIR"
    
    print_success "Directories created"
}

# Generate docker-compose.yml
create_compose_file() {
    print_info "Generating docker-compose.yml..."
    
    cat > "$INSTALL_DIR/docker-compose.yml" <<'EOF'
services:
  dns-server:
    container_name: technitium-dns
    image: technitium/dns-server:latest
    hostname: dns-server
    network_mode: host
    restart: unless-stopped
    environment:
      - DNS_SERVER_DOMAIN=dns-server
      - DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380
    volumes:
      - ./config:/etc/dns
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOF
    
    print_success "docker-compose.yml created"
}

# Pull the image first to show progress
pull_image() {
    print_info "Pulling Technitium DNS Docker image..."
    docker pull technitium/dns-server:latest
    print_success "Image pulled successfully"
}

# Start the container
start_container() {
    print_info "Starting Technitium DNS container..."
    
    cd "$INSTALL_DIR" || exit 1
    
    # Stop and remove existing container if it exists
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        print_warning "Removing existing container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi
    
    # Start with docker compose
    docker compose up -d
    
    print_success "Container started"
}

# Verify container is running
verify_installation() {
    print_info "Verifying installation..."
    
    sleep 3
    
    if ! docker ps | grep -q "$CONTAINER_NAME"; then
        print_error "Container is not running"
        print_info "Checking logs..."
        docker logs "$CONTAINER_NAME" 2>&1 | tail -20
        return 1
    fi
    
    # Check if web interface is responding
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WEB_PORT}" | grep -q "200\|302"; then
            print_success "Web interface is responding"
            return 0
        fi
        print_info "Waiting for web interface... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    print_warning "Web interface is not responding yet, but container is running"
    print_info "Check logs with: docker logs $CONTAINER_NAME"
    return 0
}

# Display final information
show_completion_info() {
    local host_ip=$(hostname -I | awk '{print $1}')
    
    print_header "Installation Complete!"
    
    echo -e "${GREEN}Technitium DNS Server is running${NC}\n"
    echo -e "Web Console:    ${YELLOW}http://${host_ip}:${WEB_PORT}${NC}"
    echo -e "                ${YELLOW}http://localhost:${WEB_PORT}${NC}"
    echo -e "\nDefault Login:  ${YELLOW}admin${NC} / ${YELLOW}admin${NC}"
    echo -e "\n${BLUE}Useful Commands:${NC}"
    echo -e "  Status:       ${YELLOW}docker ps | grep technitium${NC}"
    echo -e "  Logs:         ${YELLOW}docker logs -f $CONTAINER_NAME${NC}"
    echo -e "  Restart:      ${YELLOW}docker restart $CONTAINER_NAME${NC}"
    echo -e "  Stop:         ${YELLOW}docker stop $CONTAINER_NAME${NC}"
    echo -e "  Start:        ${YELLOW}docker start $CONTAINER_NAME${NC}"
    echo -e "  Uninstall:    ${YELLOW}cd $INSTALL_DIR && docker compose down${NC}"
    echo -e "\n${BLUE}Configuration Location:${NC} ${YELLOW}$INSTALL_DIR/config${NC}\n"
}

# ==============================================================================
# Main Execution
# ==============================================================================

main() {
    print_header "Technitium DNS Server Installer"
    
    check_root
    check_docker
    handle_port53_conflict
    create_directories
    create_compose_file
    pull_image
    start_container
    
    if verify_installation; then
        show_completion_info
        exit 0
    else
        print_error "Installation completed but verification failed"
        print_info "Check docker logs for more information"
        exit 1
    fi
}

# Run main function
main