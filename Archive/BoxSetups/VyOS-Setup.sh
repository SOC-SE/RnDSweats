#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

echo "[:] Wiping configuration and applying Quick-Start..."

configure

# ==========================================
# 0. NUCLEAR WIPE (Remove existing configs)
# ==========================================
echo "[:] Deleting existing Network, Firewall, and Routing configs..."
delete interfaces
delete protocols
delete nat
delete firewall
delete policy

# Note: We do NOT delete 'system' (preserves users/login) 
# or 'service' (preserves SSH keys/config) to avoid lockout.

# ==========================================
# 1. INTERFACE CONFIGURATION
# ==========================================
# WAN Interface
set interfaces ethernet eth0 address '10.0.100.1/16'
set interfaces ethernet eth0 description 'WAN-UPLINK'

# Internal Link to Palo Alto
set interfaces ethernet eth1 address '172.16.101.1/24'
set interfaces ethernet eth1 description 'LINK-TO-PALO'

# Internal Link to Cisco FTD
set interfaces ethernet eth2 address '172.16.102.1/24'
set interfaces ethernet eth2 description 'LINK-TO-CISCO'

# ==========================================
# 2. ROUTING
# ==========================================
# Default gateway for internet access
set protocols static route 0.0.0.0/0 next-hop '10.0.255.254'

# ==========================================
# 3. NAT (Masquerade)
# ==========================================
set nat source rule 100 outbound-interface 'eth0'
set nat source rule 100 source address '172.16.0.0/16'
set nat source rule 100 translation address 'masquerade'
set nat source rule 100 description 'OUTBOUND-ACCESS'

# ==========================================
# 4. FIREWALL (Allow All)
# ==========================================
set firewall name PERMISSIVE default-action 'accept'

# Apply PERMISSIVE to WAN (eth0)
set interfaces ethernet eth0 firewall local name PERMISSIVE
set interfaces ethernet eth0 firewall in name PERMISSIVE

# ==========================================
# 5. MANAGEMENT
# ==========================================
set service ssh port '22'
# Re-assert hostname just in case
set system host-name 'VyOS-Edge'

# Commit changes
commit
save
exit

echo "[:] Configuration Complete."
echo "[:] Verify connectivity with: run ping 10.0.255.254"