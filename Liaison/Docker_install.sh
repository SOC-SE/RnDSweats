# ==============================================================================
# File: docker_manager.sh
# Description: Manages Docker Engine on Linux: Install or Uninstall.
#              Follows official repository-based method.
#              Detects OS (Debian/Ubuntu, Fedora/CentOS/RHEL).
#              Adds current user to 'docker' group on install.
#              Verifies install with 'hello-world' container.
#              Checks for existing install/uninstall to skip as needed.
#              Optimized for MWCCDC VMs; no auto-service containerization.
#
# Dependencies: apt (Debian/Ubuntu) or dnf/yum (Fedora/CentOS/RHEL).
# Usage: sudo ./docker_manager.sh
#        Follow prompts for Install/Uninstall/Quit.
# Notes: 
# - Run as root.
# - In CCDC, ensure Docker doesn't break service scoring (e.g., expose ports manually).
# - For services (e.g., FTP from FileTransferServer2.sh), containerize manually post-install.
# ==============================================================================

#!/bin/bash

set -euo pipefail

# --- ASCII Banner ---
echo -e "\033[1;32m"
cat << "EOF"
  /====================================================\
||________                    __                    ||
||\______ \    ____    ____  |  | __  ____ _______  ||
|| |    |  \  /  _ \ _/ ___\ |  |/ /_/ __ \\_  __ \ ||
|| |    `   \(  <_> )\  \___ |    < \  ___/ |  | \/ ||
||/_______  / \____/  \___  >|__|_ \ \___  >|__|    ||
||        \/              \/      \/     \/         ||
\====================================================/
EOF
echo -e "\033[0m"
echo "Docker Manager - For MWCCDC Team Prep"
echo "-------------------------------------"

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Spinner function for progress
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "%c " "${spinstr:0:1}"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b"
    done
    printf " \b"
}

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
        QUERY_CMD="dpkg -s"
        REMOVE_CMD="apt-get purge -y"
        REMOVE_EXTRA="apt-get autoremove -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
        QUERY_CMD="rpm -q"
        REMOVE_CMD="dnf remove -y"
        REMOVE_EXTRA="dnf autoremove -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum check-update"
        QUERY_CMD="rpm -q"
        REMOVE_CMD="yum remove -y"
        REMOVE_EXTRA="yum autoremove -y"
    else
        log_error "Unsupported package manager. Only apt (Debian/Ubuntu) and dnf/yum (Fedora/CentOS/RHEL) are supported."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Check if Docker is Installed ---
is_docker_installed() {
    if command -v docker &> /dev/null; then
        return 0  # Installed
    else
        return 1  # Not installed
    fi
}

# --- Print Docker Usage Instructions ---
print_docker_instructions() {
    log_info "Docker Usage Instructions (Tailored for MWCCDC Preparation):"
    echo "Docker allows you to containerize applications for isolation, quick deployment, and security in CCDC scenarios. In MWCCDC (per 2025 Team Pack), use it on the 'Docker/Remote' VM (172.20.240.10, NAT'd to 172.25.20+team#.x) to run services without affecting host scoring. Key guidelines: Manually containerize to avoid uptime issues; expose ports via Palo Alto NAT; harden against threats like container escapes (e.g., CVE-2025 trends in AI-driven attacks on misconfigured images)."
    echo ""
    echo "**Basic Commands:**"
    echo "- Pull an image: \`docker pull <image-name>\` (e.g., \`docker pull ubuntu\` from Docker Hub)."
    echo "- Run a container: \`docker run -d --name <name> -p <host-port>:<container-port> <image>\` (detached mode, port mapping)."
    echo "- List containers: \`docker ps\` (running) or \`docker ps -a\` (all)."
    echo "- Stop/Remove: \`docker stop <name>\` then \`docker rm <name>\`."
    echo "- Build from Dockerfile: \`docker build -t <tag> .\`."
    echo ""
    echo "**CCDC-Specific Examples:**"
    echo "- Run FTP (vsftpd) in a container: \`docker run -d --name ftp-server -p 21:21 -v /host/dir:/srv/ftp fauria/vsftpd\` (mount host dir for files; expose via Palo Alto for scoring)."
    echo "- Network scanning tool (Nmap): \`docker run --rm -it instrumentisto/nmap -sV <target-ip>\` (ephemeral for threat hunting)."
    echo "- Isolate a vulnerable service: Use for quick recovery—stop/restart container without host reboot."
    echo ""
    echo "**Security Best Practices (2025 Trends):**"
    echo "- Scan images: Use Docker Scout (\`docker scout <image>\`) for vulnerabilities."
    echo "- Least privilege: Run as non-root (\`--user <uid>\`); avoid privileged mode."
    echo "- In CCDC: Monitor logs (\`docker logs <name>\`); align with MITRE ATT&CK (e.g., prevent execution via seccomp profiles). Simulate attacks on containers during prep."
    echo "- Sources: Docker Docs (docker.com), National CCDC Rules (nationalccdc.org), MWCCDC Pack."
    echo "For more, run \`docker --help\` or visit docs.docker.com. Test in lab to avoid competition pitfalls!"
}

# --- Install Docker ---
install_docker() {
    if is_docker_installed; then
        log_warn "Docker is already installed."
        return 1
    fi
    log_info "Installing Docker..."

    # Uninstall old versions with spinner and error capture
    printf "Removing any old Docker packages... "
    local err_file=$(mktemp)
    ( $REMOVE_CMD docker docker-engine docker.io containerd runc >/dev/null 2>"$err_file" || true
      $REMOVE_EXTRA >/dev/null 2>>"$err_file" || true ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during removal of old packages:${NC}"
        echo "$err_content"
        log_error "Removal of old Docker packages failed."
    fi
    echo ""  # Newline

    # Main installation with spinner and error capture
    printf "Installing Docker... "
    local err_file=$(mktemp)
    if [ "$PKG_MANAGER" = "apt" ]; then
        ( $UPDATE_CMD >/dev/null 2>"$err_file"
          $INSTALL_CMD ca-certificates curl gnupg >/dev/null 2>>"$err_file"
          install -m 0755 -d /etc/apt/keyrings >/dev/null 2>>"$err_file"
          curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>>"$err_file"
          chmod a+r /etc/apt/keyrings/docker.gpg >/dev/null 2>>"$err_file"
          echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            tee /etc/apt/sources.list.d/docker.list >/dev/null 2>>"$err_file"
          $UPDATE_CMD >/dev/null 2>>"$err_file"
          $INSTALL_CMD docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>>"$err_file" ) &
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        if [ "$PKG_MANAGER" = "dnf" ]; then
            ( $INSTALL_CMD dnf-plugins-core >/dev/null 2>"$err_file"
              dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>>"$err_file"
              $INSTALL_CMD docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>>"$err_file" ) &
        else
            ( $INSTALL_CMD yum-utils >/dev/null 2>"$err_file"
              yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>>"$err_file"
              $INSTALL_CMD docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>>"$err_file" ) &
        fi
    else
        log_error "Unsupported operating system."
    fi
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during Docker installation:${NC}"
        echo "$err_content"
        log_error "Docker installation failed."
    fi
    echo ""  # Newline

    # Post-install with spinner and error capture
    printf "Configuring Docker service... "
    local err_file=$(mktemp)
    ( systemctl start docker >/dev/null 2>"$err_file"
      systemctl enable docker >/dev/null 2>>"$err_file"
      usermod -aG docker "${SUDO_USER:-$(whoami)}" >/dev/null 2>>"$err_file" || true ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during Docker configuration:${NC}"
        echo "$err_content"
        log_error "Docker configuration failed."
    fi
    echo ""  # Newline

    # Verify with spinner and error capture
    printf "Verifying Docker installation... "
    local err_file=$(mktemp)
    ( docker run hello-world >/dev/null 2>"$err_file" ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during Docker verification:${NC}"
        echo "$err_content"
        log_error "Docker verification failed."
    fi
    echo ""  # Newline

    log_info "Docker installed successfully."
    
    # Display usage instructions
    print_docker_instructions
    return 0
}

# --- Uninstall Docker ---
uninstall_docker() {
    if ! is_docker_installed; then
        log_warn "Docker is not installed."
        return 1
    fi
    log_info "Uninstalling Docker..."

    # Uninstall with spinner and error capture
    printf "Uninstalling Docker... "
    local err_file=$(mktemp)
    ( # Stop and disable service
      systemctl stop docker >/dev/null 2>"$err_file" || true
      systemctl disable docker >/dev/null 2>>"$err_file" || true

      # Remove packages
      $REMOVE_CMD docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker docker-engine docker.io runc >/dev/null 2>>"$err_file" || true
      $REMOVE_EXTRA >/dev/null 2>>"$err_file" || true

      # Clean up configs and data (caution: removes images/volumes)
      rm -rf /var/lib/docker /etc/docker /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.gpg >/dev/null 2>>"$err_file" || true

      # Remove docker group if empty
      if getent group docker > /dev/null; then
          groupdel docker >/dev/null 2>>"$err_file" || true
      fi ) &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ -n "$err_content" ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Errors/Warnings:${NC}"
        echo "$err_content"
    fi
    if [ $exit_status -ne 0 ]; then
        log_error "Docker uninstallation failed."
    fi
    if [ -z "$err_content" ]; then
        echo ""  # Newline only if no errors
    fi

    log_info "Docker uninstalled successfully."
    return 0
}

# --- Prompt for Mode ---
prompt_mode() {
    log_info "Select mode:"
    echo "1) Install Docker"
    echo "2) Uninstall Docker"
    echo "3) Quit"
    read -p "Enter your choice (1-3): " mode
    case "$mode" in
        1) 
            read -p "Are you sure you want to install Docker? (y/n): " confirm
            if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                install_docker
                if [ $? -eq 0 ]; then
                    log_info "Installation complete."
                fi
            else
                log_warn "Installation cancelled."
            fi
            ;;
        2) 
            read -p "Are you sure you want to uninstall Docker? (y/n): " confirm
            if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                uninstall_docker
                if [ $? -eq 0 ]; then
                    log_info "Uninstallation complete."
                fi
            else
                log_warn "Uninstallation cancelled."
            fi
            ;;
        3) 
            log_info "Exiting script."
            exit 0
            ;;
        *) log_error "Invalid choice. Please select 1, 2, or 3." ;;
    esac
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    prompt_mode
    log_info "${GREEN}--- Script Complete ---${NC}"
}

main "$@"