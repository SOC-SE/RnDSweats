# ==============================================================================
# Network Audit - Windows
# Comprehensive network security check
# ==============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NETWORK AUDIT - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] LISTENING PORTS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{
    Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}
} | Sort-Object LocalPort | Format-Table -AutoSize

Write-Host "`n[2/12] ESTABLISHED CONNECTIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{
    Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}
} | Format-Table -AutoSize

Write-Host "`n[3/12] CONNECTIONS BY REMOTE IP" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "0.0.0.0"} |
    Group-Object RemoteAddress | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host "`n[4/12] SUSPICIOUS PORTS (Common Backdoors)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$suspiciousPorts = @(4444, 5555, 6666, 7777, 1337, 31337, 12345, 54321, 9001, 9002, 8080, 8443, 3389, 5985, 5986)
Get-NetTCPConnection | Where-Object {$suspiciousPorts -contains $_.LocalPort -or $suspiciousPorts -contains $_.RemotePort} |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{
        Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}
    } | Format-Table -AutoSize

Write-Host "`n[5/12] FIREWALL STATUS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize

Write-Host "`n[6/12] FIREWALL RULES (Inbound Allow)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | 
    Select-Object DisplayName, Profile, @{Name="LocalPort";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}} | 
    Format-Table -AutoSize | Select-Object -First 30

Write-Host "`n[7/12] NETWORK ADAPTERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed | Format-Table -AutoSize

Write-Host "`n[8/12] IP CONFIGURATION" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"} | 
    Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize

Write-Host "`n[9/12] DNS SERVERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | 
    Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize

Write-Host "`n[10/12] ARP TABLE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable"} | 
    Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State | Format-Table -AutoSize

Write-Host "`n[11/12] ROUTING TABLE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetRoute | Where-Object {$_.DestinationPrefix -ne "ff00::/8"} | 
    Select-Object DestinationPrefix, NextHop, InterfaceAlias | Format-Table -AutoSize

Write-Host "`n[12/12] HOSTS FILE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Content "C:\Windows\System32\drivers\etc\hosts" | Where-Object {$_ -notmatch "^#" -and $_ -ne ""}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "NETWORK AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
