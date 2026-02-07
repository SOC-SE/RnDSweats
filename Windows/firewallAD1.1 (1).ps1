#--------------------------------------------------------------
# AD | Firewall
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
# AD | 1.0
#--------------------------------------------------------------


#DNS
New-NetFirewallRule -DisplayName "DNS TCP Inbound Port 53" -Direction Inbound -LocalPort 53 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "DNS TCP Outbound Port 53" -Direction Outbound -LocalPort 53 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "DNS UDP Inbound Port 53" -Direction Inbound -LocalPort 53 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "DNS UDP Outbound Port 53" -Direction Outbound -LocalPort 53 -Protocol UDP  -Action Allow

#Kerberos authentication
New-NetFirewallRule -DisplayName "Kerberos authentication TCP Inbound Port 88" -Direction Inbound -LocalPort 88 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Kerberos authentication TCP Outbound Port 88" -Direction Outbound -LocalPort 88 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Kerberos authentication UDP Inbound Port 88" -Direction Inbound -LocalPort 88 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "Kerberos authentication UDP Outbound Port 88" -Direction Outbound -LocalPort 88 -Protocol UDP  -Action Allow

#W32Time
New-NetFirewallRule -DisplayName "W32Time UDP Inbound Port 123" -Direction Inbound -LocalPort 123 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "W32Time UDP Outbound Port 123" -Direction Outbound -LocalPort 123 -Protocol UDP  -Action Allow

#RPC Endpoint Mapper
New-NetFirewallRule -DisplayName "RPC Endpoint Mapper TCP Inbound Port 135" -Direction Inbound -LocalPort 135 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "RPC Endpoint Mapper TCP Outbound Port 135" -Direction Outbound -LocalPort 135 -Protocol TCP  -Action Allow

#NetBIOS
New-NetFirewallRule -DisplayName "NetBIOS UDP Inbound Port 137" -Direction Inbound -LocalPort 137 -Protocol UDP  -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS UDP Outbound Port 137" -Direction Outbound -LocalPort 137 -Protocol UDP  -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS UDP Inbound Port 138" -Direction Inbound -LocalPort 138 -Protocol UDP  -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS UDP Outbound Port 138" -Direction Outbound -LocalPort 138  -Protocol UDP  -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS TCP Inbound Port 139" -Direction Inbound -LocalPort 139 -Protocol TCP  -Action Deny

New-NetFirewallRule -DisplayName "NetBIOS TCP Outbound Port 139" -Direction Outbound -LocalPort 139 -Protocol TCP  -Action Deny

#LLMNR (anti-Responder)
New-NetFirewallRule -DisplayName "LLMNR UDP Inbound Port 5355 DENY" -Direction Inbound -LocalPort 5355 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "LLMNR UDP Outbound Port 5355 DENY" -Direction Outbound -LocalPort 5355 -Protocol UDP -Action Deny

#mDNS (anti-Responder)
New-NetFirewallRule -DisplayName "mDNS UDP Inbound Port 5353 DENY" -Direction Inbound -LocalPort 5353 -Protocol UDP -Action Deny

New-NetFirewallRule -DisplayName "mDNS UDP Outbound Port 5353 DENY" -Direction Outbound -LocalPort 5353 -Protocol UDP -Action Deny

#LDAP
New-NetFirewallRule -DisplayName "LDAP UDP Inbound Port 389" -Direction Inbound -LocalPort 389 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "LDAP UDP Outbound Port 389" -Direction Outbound -LocalPort 389  -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "LDAP TCP Inbound Port 389" -Direction Inbound -LocalPort 389 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "LDAP TCP Outbound Port 389" -Direction Outbound -LocalPort 389 -Protocol TCP  -Action Allow

#SMB
New-NetFirewallRule -DisplayName "SMB TCP Inbound Port 445" -Direction Inbound -LocalPort 445 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "SMB TCP Outbound Port 445" -Direction Outbound -LocalPort 445 -Protocol TCP  -Action Allow

#Kerberos password change
New-NetFirewallRule -DisplayName "Kerberos password change Inbound Port 464" -Direction Inbound -LocalPort 464 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "Kerberos password change Outbound Port 464" -Direction Outbound -LocalPort 464  -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "Kerberos password change Inbound Port 464" -Direction Inbound -LocalPort 464 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Kerberos password change Outbound Port 464" -Direction Outbound -LocalPort 464 -Protocol TCP  -Action Allow

#LDAP SSL
New-NetFirewallRule -DisplayName "LDAP SSL TCP Inbound Port 636" -Direction Inbound -LocalPort 636 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "LDAP SSL TCP Outbound Port 636" -Direction Outbound -LocalPort 636 -Protocol TCP  -Action Allow

#Active Directory Web Services (ADWS)
New-NetFirewallRule -DisplayName "Active Directory Web Services ADWS Inbound Port 9389" -Direction Inbound -LocalPort 9389 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Active Directory Web Services ADWS TCP Outbound Port 9389" -Direction Outbound -LocalPort 9389 -Protocol TCP  -Action Allow

#LDAP Global Catalog
New-NetFirewallRule -DisplayName "LDAP Global Catalog TCP Inbound Port 3268" -Direction Inbound -LocalPort 3268 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "LDAP Global Catalog TCP Outbound Port 3268" -Direction Outbound -LocalPort 3268 -Protocol TCP  -Action Allow

#LDAP GC SSL
New-NetFirewallRule -DisplayName "LDAP GC SSL Inbound Port 3269" -Direction Inbound -LocalPort 3269 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "LDAP GC SSL TCP Outbound Port 3269" -Direction Outbound -LocalPort 3269 -Protocol TCP  -Action Allow

#--------------------------------------------------------------
# DNS | 1.0
#--------------------------------------------------------------

New-NetFirewallRule -DisplayName "DNS Lookups Inbound Port 53" -Direction Inbound -LocalPort 53 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "DNS Lookups Outbound Port 53" -Direction Outbound -LocalPort 53 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Large responses & zone Transfers Inbound Port 53" -Direction Inbound -LocalPort 53 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "Large responses & zone Transfers Outbound Port 53" -Direction Outbound -LocalPort 53 -Protocol UDP  -Action Allow

New-NetFirewallRule -DisplayName "DNS over TLS Inbound Port 853" -Direction Inbound -LocalPort 853 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "DNS over TLS Outbound Port 853" -Direction Outbound -LocalPort 853 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "DNS over HTTPS Inbound Port 443" -Direction Inbound -LocalPort 443 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "DNS over HTTPS Outbound Port 443" -Direction Outbound -LocalPort 443 -Protocol TCP  -Action Allow

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

New-NetFirewallRule -DisplayName "Cisco Fire Power Inbound Port 443" -Direction Inbound -LocalPort 443 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Outbound Port 443" -Direction Outbound -LocalPort 443 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Inbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP  -Action Allow

New-NetFirewallRule -DisplayName "Cisco Fire Power Outbound Port 80" -Direction Outbound -LocalPort 80 -Protocol TCP  -Action Allow

#--------------------------------------------------------------
# SQL | 1.2
#--------------------------------------------------------------

#Inbound
New-NetFirewallRule -DisplayName "SQL Inbound Port 3306" -Direction Inbound -LocalPort 3306 -Protocol TCP  -Action Allow

#Outbound
New-NetFirewallRule -DisplayName "SQL Outbound Port 3306" -Direction Outbound -LocalPort 3306 -Protocol TCP -Action Allow

#Inbound
New-NetFirewallRule -DisplayName "SQL Sec Inbound Port 3300" -Direction Inbound -LocalPort 3300 -Protocol TCP  -Action Allow

#Outbound
New-NetFirewallRule -DisplayName "SQL Sec Outbound Port 3300" -Direction Outbound -LocalPort 3300 -Protocol TCP -Action Allow
