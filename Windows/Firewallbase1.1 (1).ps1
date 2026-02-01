#--------------------------------------------------------------
#Base Firewall
# Made by Logan Schultz
# Version | 1.1
#--------------------------------------------------------------

#--------------------------------------------------------------
# Backups | 1.0
#--------------------------------------------------------------
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#--------------------------------------------------------------
# Disable all rules | 1.0
#--------------------------------------------------------------
Get-NetFirewallRule | Disable-NetFirewallRule
#--------------------------------------------------------------
# Splunk FORWARDER / Splunk SERVER | 1.0
#--------------------------------------------------------------

#OutBound | SERVER
New-NetFirewallRule -DisplayName "Wazuh AGENT Inbound Port 1514" -Direction Inbound -LocalPort 8000 -Protocol TCP  -Action Allow

#OutBound | SERVER
New-NetFirewallRule -DisplayName "Wazuh AGENT Inbound Port 1515" -Direction Inbound -LocalPort 8089 -Protocol TCP -Action Block

#OutBound | SERVER
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 1514" -Direction Inbound -LocalPort 9997 -Protocol TCP  -Action Allow

#OutBound | SERVER
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 1515" -Direction Inbound -LocalPort 514 -Protocol TCP  -Action Allow

#Inbound | FORWARDER
New-NetFirewallRule -DisplayName "Wazuh FORWARDER OutBound Port 9997" -Direction Outbound -LocalPort 9997 -Protocol TCP -Action Block

#Inbound | FORWARDER
New-NetFirewallRule -DisplayName "Wazuh FORWARDER OutBound Port 8089" -Direction Outbound -LocalPort 8089 -Protocol TCP  -Action Allow

#--------------------------------------------------------------
# Wazuh AGENT / Wazuh Server | 1.0
#--------------------------------------------------------------

#OutBound | AGENT
New-NetFirewallRule -DisplayName "Wazuh AGENT Outbound Port 1514" -Direction Outbound -LocalPort 1514 -Protocol TCP  -Action Allow

#OutBound | AGENT
New-NetFirewallRule -DisplayName "Wazuh AGENT Outbound Port 1515" -Direction Outbound -LocalPort 1515 -Protocol TCP -Action Block

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 1514" -Direction Inbound -LocalPort 1514 -Protocol TCP  -Action Allow

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 1515" -Direction Inbound -LocalPort 1515 -Protocol TCP  -Action Allow

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 55000" -Direction Inbound -LocalPort 55000 -Protocol TCP -Action Block

#Inbound | Server
New-NetFirewallRule -DisplayName "Wazuh Server Inbound Port 443" -Direction Inbound -LocalPort 443 -Protocol TCP  -Action Allow

#--------------------------------------------------------------
# Salt MINION | 1.0
#--------------------------------------------------------------

#Inbound
New-NetFirewallRule -DisplayName "Salt MINION Inbound Port 4505" -Direction Inbound -LocalPort 4505 -Protocol TCP  -Action Allow

#OutBound
New-NetFirewallRule -DisplayName "Salt MINION Outbound Port 4505" -Direction Outbound -LocalPort 4505 -Protocol TCP -Action Block

#Inbound
New-NetFirewallRule -DisplayName "Salt MINION Inbound Port 4506" -Direction Inbound -LocalPort 4506 -Protocol TCP  -Action Allow

#OutBound
New-NetFirewallRule -DisplayName "Salt MINION Outbound Port 4506" -Direction Outbound -LocalPort 4506 -Protocol TCP -Action Block

#--------------------------------------------------------------
# VELOCIRAPTOR | 1.0
#--------------------------------------------------------------

#Inbound
New-NetFirewallRule -DisplayName "VELOCIRAPTOR Inbound Port 8001" -Direction Inbound -LocalPort 8001 -Protocol TCP  -Action Allow

#OutBound
New-NetFirewallRule -DisplayName "VELOCIRAPTOR Outbound Port 8001" -Direction Outbound -LocalPort 8001 -Protocol TCP -Action Block

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

New-NetFirewallRule -DisplayName "Cisco Fire Power Inbound Port 443" -Direction Inbound -LocalPort 443 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Outbound Port 443" -Direction Outbound -LocalPort 443 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Inbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP  -Action Allow


New-NetFirewallRule -DisplayName "Cisco Fire Power Outbound Port 80" -Direction Outbound -LocalPort 80 -Protocol TCP  -Action Allow
