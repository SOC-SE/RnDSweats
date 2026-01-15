#!/bin/bash
# RDP Setup Script for Kali Linux / Parrot OS
# Configures xrdp with a dedicated user for Guacamole integration

set -e

# Configuration
RDP_USER="rdpuser"
RDP_PASS=""  # Will be generated or prompted
RDP_PORT=3389

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Detect distro
detect_distro() {
    if grep -qi "kali" /etc/os-release 2>/dev/null; then
        DISTRO="kali"
    elif grep -qi "parrot" /etc/os-release 2>/dev/null; then
        DISTRO="parrot"
    elif grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        DISTRO="debian"
    else
        warn "Unknown distribution, assuming Debian-based"
        DISTRO="debian"
    fi
    log "Detected distribution: $DISTRO"
}

# Parse arguments
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -u, --user USERNAME    RDP username (default: rdpuser)"
    echo "  -p, --password PASS    RDP password (default: auto-generated)"
    echo "  -P, --port PORT        RDP port (default: 3389)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --user rdpuser --password MySecurePass123"
    echo "  $0 -p \$(openssl rand -base64 16)"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            RDP_USER="$2"
            shift 2
            ;;
        -p|--password)
            RDP_PASS="$2"
            shift 2
            ;;
        -P|--port)
            RDP_PORT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Generate password if not provided
if [[ -z "$RDP_PASS" ]]; then
    RDP_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    log "Generated random password for $RDP_USER"
fi

detect_distro

log "Starting RDP setup for Guacamole integration"
info "User: $RDP_USER"
info "Port: $RDP_PORT"

# Update package lists
log "Updating package lists..."
apt-get update

# Install xrdp and dependencies
log "Installing xrdp and desktop dependencies..."
apt-get install -y \
    xrdp \
    xorgxrdp \
    dbus-x11 \
    xfce4 \
    xfce4-goodies \
    xfce4-terminal \
    tigervnc-standalone-server \
    tigervnc-common

# Create RDP user if doesn't exist
if id "$RDP_USER" &>/dev/null; then
    log "User $RDP_USER already exists, updating password..."
else
    log "Creating user $RDP_USER..."
    useradd -m -s /bin/bash -G sudo,audio,video,plugdev "$RDP_USER"
fi

# Set password
echo "$RDP_USER:$RDP_PASS" | chpasswd
log "Password set for $RDP_USER"

# Configure xrdp port
log "Configuring xrdp on port $RDP_PORT..."
sed -i "s/^port=.*/port=$RDP_PORT/" /etc/xrdp/xrdp.ini

# Configure xrdp for better performance with Guacamole
log "Optimizing xrdp settings..."

# Update main xrdp.ini for performance
sed -i 's/^max_bpp=.*/max_bpp=24/' /etc/xrdp/xrdp.ini
sed -i 's/^xserverbpp=.*/xserverbpp=24/' /etc/xrdp/xrdp.ini

# Ensure crypt_level is set appropriately
sed -i 's/^crypt_level=.*/crypt_level=high/' /etc/xrdp/xrdp.ini

# Configure session to use XFCE
log "Configuring XFCE desktop session..."

# Create .xsession for the rdp user
cat > /home/$RDP_USER/.xsession << 'EOF'
#!/bin/bash
# Fix for authentication issues
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR

# Set session type
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=XFCE

# Start XFCE
exec startxfce4
EOF

chmod +x /home/$RDP_USER/.xsession
chown $RDP_USER:$RDP_USER /home/$RDP_USER/.xsession

# Also create .xinitrc as fallback
cp /home/$RDP_USER/.xsession /home/$RDP_USER/.xinitrc
chown $RDP_USER:$RDP_USER /home/$RDP_USER/.xinitrc

# Configure startwm.sh
log "Configuring startwm.sh..."
cat > /etc/xrdp/startwm.sh << 'EOF'
#!/bin/bash

# Unset problematic environment variables
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR

# Check for user .xsession first
if [ -x ~/.xsession ]; then
    exec ~/.xsession
fi

# Check for user .xinitrc
if [ -x ~/.xinitrc ]; then
    exec ~/.xinitrc
fi

# Fallback to XFCE
if command -v startxfce4 &> /dev/null; then
    exec startxfce4
fi

# Last resort - try to find any desktop
for desktop in startxfce4 startlxde startmate-session gnome-session startkde startplasma-x11; do
    if command -v $desktop &> /dev/null; then
        exec $desktop
    fi
done

# Absolute fallback
exec xterm
EOF

chmod +x /etc/xrdp/startwm.sh

# Fix polkit for colord (common issue on Kali/Parrot)
log "Configuring PolicyKit rules..."
mkdir -p /etc/polkit-1/localauthority/50-local.d

cat > /etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla << 'EOF'
[Allow Colord all Users]
Identity=unix-user:*
Action=org.freedesktop.color-manager.create-device;org.freedesktop.color-manager.create-profile;org.freedesktop.color-manager.delete-device;org.freedesktop.color-manager.delete-profile;org.freedesktop.color-manager.modify-device;org.freedesktop.color-manager.modify-profile
ResultAny=no
ResultInactive=no
ResultActive=yes
EOF

# Also create rules.d version for newer polkit
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/02-allow-colord.rules << 'EOF'
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.color-manager.create-device" ||
         action.id == "org.freedesktop.color-manager.create-profile" ||
         action.id == "org.freedesktop.color-manager.delete-device" ||
         action.id == "org.freedesktop.color-manager.delete-profile" ||
         action.id == "org.freedesktop.color-manager.modify-device" ||
         action.id == "org.freedesktop.color-manager.modify-profile") &&
        subject.isInGroup("users")) {
        return polkit.Result.YES;
    }
});
EOF

# Fix for black screen / authentication issues
log "Applying session fixes..."

# Ensure ssl directory exists
mkdir -p /etc/xrdp/ssl

# Generate new SSL cert if needed
if [[ ! -f /etc/xrdp/cert.pem ]] || [[ ! -f /etc/xrdp/key.pem ]]; then
    log "Generating xrdp SSL certificates..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/xrdp/key.pem \
        -out /etc/xrdp/cert.pem \
        -days 3650 -nodes \
        -subj "/C=US/ST=State/L=City/O=Org/CN=$(hostname)"
    chmod 600 /etc/xrdp/key.pem
fi

# Add xrdp user to ssl-cert group
usermod -aG ssl-cert xrdp 2>/dev/null || true

# Configure sesman
log "Configuring xrdp-sesman..."
sed -i 's/^AllowRootLogin=.*/AllowRootLogin=false/' /etc/xrdp/sesman.ini
sed -i 's/^MaxSessions=.*/MaxSessions=10/' /etc/xrdp/sesman.ini

# Enable and restart services
log "Enabling and starting xrdp services..."
systemctl daemon-reload
systemctl enable xrdp
systemctl enable xrdp-sesman
systemctl restart xrdp-sesman
systemctl restart xrdp

# Wait for service to start
sleep 3

# Verify service is running
if systemctl is-active --quiet xrdp; then
    log "xrdp service is running"
else
    error "xrdp service failed to start. Check: journalctl -u xrdp"
fi

# Configure firewall if ufw is present
if command -v ufw &> /dev/null; then
    log "Configuring UFW firewall..."
    ufw allow $RDP_PORT/tcp comment "RDP for Guacamole" 2>/dev/null || true
fi

# Get IP addresses
IP_ADDR=$(hostname -I | awk '{print $1}')

# Save credentials
CREDS_FILE="/root/rdp-credentials.txt"
cat > "$CREDS_FILE" << EOF
RDP Configuration for Guacamole
================================
Generated: $(date)
Hostname: $(hostname)

Connection Details:
  IP Address: $IP_ADDR
  Port: $RDP_PORT
  Username: $RDP_USER
  Password: $RDP_PASS

Guacamole Connection Settings:
  Protocol: RDP
  Hostname: $IP_ADDR
  Port: $RDP_PORT
  Username: $RDP_USER
  Password: $RDP_PASS
  Security mode: NLA (or "any" if issues)
  Ignore server certificate: Yes
  Color depth: True color (24-bit)

Troubleshooting:
  - Check xrdp status: systemctl status xrdp
  - View logs: journalctl -u xrdp -f
  - Test locally: xfreerdp /v:localhost /u:$RDP_USER
EOF

chmod 600 "$CREDS_FILE"

# Print summary
echo ""
echo "=============================================="
echo -e "${GREEN}RDP Setup Complete!${NC}"
echo "=============================================="
echo ""
echo -e "IP Address:  ${CYAN}$IP_ADDR${NC}"
echo -e "Port:        ${CYAN}$RDP_PORT${NC}"
echo -e "Username:    ${CYAN}$RDP_USER${NC}"
echo -e "Password:    ${CYAN}$RDP_PASS${NC}"
echo ""
echo "Guacamole Connection Parameters:"
echo "--------------------------------"
echo "  Protocol:           rdp"
echo "  Hostname:           $IP_ADDR"
echo "  Port:               $RDP_PORT"
echo "  Username:           $RDP_USER"
echo "  Password:           $RDP_PASS"
echo "  Security mode:      nla"
echo "  Ignore certificate: true"
echo ""
echo -e "Credentials saved to: ${YELLOW}$CREDS_FILE${NC}"
echo ""
echo "Test connection locally:"
echo "  xfreerdp /v:localhost:$RDP_PORT /u:$RDP_USER /p:'$RDP_PASS'"
echo ""