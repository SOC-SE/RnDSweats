#--------------------------------------------------------------
#Base Firewall
# Made by Logan Schultz
# Version | 1.2
#--------------------------------------------------------------

#--------------------------------------------------------------
# Backups | 1.0
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force | Out-Null
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#--------------------------------------------------------------
# Disable all rules | 1.0
#--------------------------------------------------------------
Get-NetFirewallRule | Disable-NetFirewallRule

#--------------------------------------------------------------
# DNS | 1.2 (added - base script was missing DNS rules)
#--------------------------------------------------------------

New-NetFirewallRule -DisplayName "DNS TCP Inbound Port 53" -Direction Inbound -LocalPort 53 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "DNS TCP Outbound Port 53" -Direction Outbound -RemotePort 53 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "DNS UDP Inbound Port 53" -Direction Inbound -LocalPort 53 -Protocol UDP -Action Allow

New-NetFirewallRule -DisplayName "DNS UDP Outbound Port 53" -Direction Outbound -RemotePort 53 -Protocol UDP -Action Allow

#--------------------------------------------------------------
# Splunk FORWARDER / Splunk SERVER | 1.2
#--------------------------------------------------------------

#Inbound | SERVER
New-NetFirewallRule -DisplayName "Splunk SERVER Inbound Port 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow

#Inbound | SERVER
New-NetFirewallRule -DisplayName "Splunk SERVER Inbound Port 8089" -Direction Inbound -LocalPort 8089 -Protocol TCP -Action Allow

#Inbound | SERVER
New-NetFirewallRule -DisplayName "Splunk SERVER Inbound Port 9997" -Direction Inbound -LocalPort 9997 -Protocol TCP -Action Allow

#Inbound | SERVER
New-NetFirewallRule -DisplayName "Splunk SERVER Inbound Port 514" -Direction Inbound -LocalPort 514 -Protocol TCP -Action Allow

#Outbound | FORWARDER
New-NetFirewallRule -DisplayName "Splunk FORWARDER Outbound Port 9997" -Direction Outbound -RemotePort 9997 -Protocol TCP -Action Allow

#Outbound | FORWARDER
New-NetFirewallRule -DisplayName "Splunk FORWARDER Outbound Port 8089" -Direction Outbound -RemotePort 8089 -Protocol TCP -Action Allow

#--------------------------------------------------------------
# Wazuh AGENT / Wazuh Server | 1.2
#--------------------------------------------------------------

#Outbound | AGENT
New-NetFirewallRule -DisplayName "Wazuh AGENT Outbound Port 1514" -Direction Outbound -RemotePort 1514 -Protocol TCP -Action Allow

#Outbound | AGENT
New-NetFirewallRule -DisplayName "Wazuh AGENT Outbound Port 1515" -Direction Outbound -RemotePort 1515 -Protocol TCP -Action Allow

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 1514" -Direction Inbound -LocalPort 1514 -Protocol TCP -Action Allow

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 1515" -Direction Inbound -LocalPort 1515 -Protocol TCP -Action Allow

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 55000" -Direction Inbound -LocalPort 55000 -Protocol TCP -Action Allow

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow

#--------------------------------------------------------------
# Salt MINION | 1.2
#--------------------------------------------------------------

#Inbound
New-NetFirewallRule -DisplayName "Salt MINION Inbound Port 4505" -Direction Inbound -LocalPort 4505 -Protocol TCP -Action Allow

#Outbound
New-NetFirewallRule -DisplayName "Salt MINION Outbound Port 4505" -Direction Outbound -RemotePort 4505 -Protocol TCP -Action Allow

#Inbound
New-NetFirewallRule -DisplayName "Salt MINION Inbound Port 4506" -Direction Inbound -LocalPort 4506 -Protocol TCP -Action Allow

#Outbound
New-NetFirewallRule -DisplayName "Salt MINION Outbound Port 4506" -Direction Outbound -RemotePort 4506 -Protocol TCP -Action Allow

#--------------------------------------------------------------
# VELOCIRAPTOR | 1.2
#--------------------------------------------------------------

#Inbound
New-NetFirewallRule -DisplayName "VELOCIRAPTOR Inbound Port 8001" -Direction Inbound -LocalPort 8001 -Protocol TCP -Action Allow

#Outbound
New-NetFirewallRule -DisplayName "VELOCIRAPTOR Outbound Port 8001" -Direction Outbound -RemotePort 8001 -Protocol TCP -Action Allow

#--------------------------------------------------------------
# RDP Whitelist | 1.0
#--------------------------------------------------------------
#New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 192.168.1.100 -Action Allow

#--------------------------------------------------------------
# Palo Alto Mgmt | 1.0
#--------------------------------------------------------------

#--------------------------------------------------------------
# Cisco Fire Power  Mgmt | 1.0
#--------------------------------------------------------------

New-NetFirewallRule -DisplayName "Cisco Fire Power Inbound Port 443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Outbound Port 443" -Direction Outbound -RemotePort 443 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Inbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Outbound Port 80" -Direction Outbound -RemotePort 80 -Protocol TCP -Action Allow

#--------------------------------------------------------------
# LLMNR / mDNS / NetBIOS Deny (anti-Responder) | 1.2
#--------------------------------------------------------------

#NetBIOS
New-NetFirewallRule -DisplayName "NetBIOS UDP Inbound Port 137 DENY" -Direction Inbound -LocalPort 137 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS UDP Outbound Port 137 DENY" -Direction Outbound -LocalPort 137 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS UDP Inbound Port 138 DENY" -Direction Inbound -LocalPort 138 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS UDP Outbound Port 138 DENY" -Direction Outbound -LocalPort 138 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS TCP Inbound Port 139 DENY" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS TCP Outbound Port 139 DENY" -Direction Outbound -LocalPort 139 -Protocol TCP -Action Deny

#LLMNR
New-NetFirewallRule -DisplayName "LLMNR UDP Inbound Port 5355 DENY" -Direction Inbound -LocalPort 5355 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "LLMNR UDP Outbound Port 5355 DENY" -Direction Outbound -LocalPort 5355 -Protocol UDP -Action Deny

#mDNS
New-NetFirewallRule -DisplayName "mDNS UDP Inbound Port 5353 DENY" -Direction Inbound -LocalPort 5353 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "mDNS UDP Outbound Port 5353 DENY" -Direction Outbound -LocalPort 5353 -Protocol UDP -Action Deny
