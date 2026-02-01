# ==============================================================================
# Network Audit - Windows
# Comprehensive network security check
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

#Requires -Version 5.1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NETWORK AUDIT - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] LISTENING PORTS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess, @{
        Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}
    } | Sort-Object LocalPort | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve listening ports" -ForegroundColor Red
}

Write-Host "`n[2/12] ESTABLISHED CONNECTIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{
        Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}
    } | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve established connections" -ForegroundColor Red
}

Write-Host "`n[3/12] CONNECTIONS BY REMOTE IP" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {$_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "0.0.0.0"} |
        Group-Object RemoteAddress | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
} catch {
    Write-Host "Unable to group connections" -ForegroundColor Red
}

Write-Host "`n[4/12] SUSPICIOUS PORTS (Common Backdoors)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$suspiciousPorts = @(4444, 5555, 6666, 7777, 1337, 31337, 12345, 54321, 9001, 9002, 8080, 8443, 3389, 5985, 5986)
try {
    $suspicious = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {$suspiciousPorts -contains $_.LocalPort -or $suspiciousPorts -contains $_.RemotePort}
    if ($suspicious) {
        $suspicious | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{
            Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}
        } | Format-Table -AutoSize
    } else {
        Write-Host "None found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check suspicious ports" -ForegroundColor Red
}

Write-Host "`n[5/12] FIREWALL STATUS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve firewall status" -ForegroundColor Red
}

Write-Host "`n[6/12] FIREWALL RULES (Inbound Allow)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Select-Object -First 30 DisplayName, Profile | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve firewall rules" -ForegroundColor Red
}

Write-Host "`n[7/12] NETWORK ADAPTERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Select-Object Name, Status, MacAddress, LinkSpeed | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve adapters" -ForegroundColor Red
}

Write-Host "`n[8/12] IP CONFIGURATION" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetIPAddress -ErrorAction SilentlyContinue |
        Where-Object {$_.AddressFamily -eq "IPv4"} |
        Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve IP config" -ForegroundColor Red
}

Write-Host "`n[9/12] DNS SERVERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object {$_.ServerAddresses} |
        Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve DNS servers" -ForegroundColor Red
}

Write-Host "`n[10/12] ARP TABLE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetNeighbor -ErrorAction SilentlyContinue |
        Where-Object {$_.State -ne "Unreachable"} |
        Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve ARP table" -ForegroundColor Red
}

Write-Host "`n[11/12] ROUTING TABLE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object {$_.DestinationPrefix -ne "ff00::/8"} |
        Select-Object -First 20 DestinationPrefix, NextHop, InterfaceAlias | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve routes" -ForegroundColor Red
}

Write-Host "`n[12/12] HOSTS FILE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        Get-Content $hostsFile | Where-Object {$_ -notmatch "^#" -and $_ -ne ""}
    } else {
        Write-Host "Hosts file not found" -ForegroundColor Red
    }
} catch {
    Write-Host "Unable to read hosts file" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "NETWORK AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
