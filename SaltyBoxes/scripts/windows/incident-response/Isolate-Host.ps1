# ==============================================================================
# Host Isolation Script - Windows
# Immediately isolate a compromised host while maintaining Salt connectivity
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$SaltMasterIP
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "HOST ISOLATION - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Try to detect Salt master if not provided
if (-not $SaltMasterIP) {
    try {
        $minionConfig = Get-Content "C:\ProgramData\Salt Project\Salt\conf\minion" -ErrorAction SilentlyContinue
        $SaltMasterIP = ($minionConfig | Where-Object {$_ -match "^master:"}).Split(":")[1].Trim()
    } catch {
        Write-Host "ERROR: Salt master IP required. Usage: .\Isolate-Host.ps1 -SaltMasterIP <IP>" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nSalt Master IP: $SaltMasterIP" -ForegroundColor Yellow

Write-Host "`n[1/5] ENABLING WINDOWS FIREWALL (ALL PROFILES)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "Firewall enabled on all profiles"

Write-Host "`n[2/5] BLOCKING ALL INBOUND/OUTBOUND BY DEFAULT" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
Write-Host "Default policies set to Block"

Write-Host "`n[3/5] CREATING SALT COMMUNICATION RULES" -ForegroundColor Yellow
Write-Host "----------------------------------------"

# Remove any existing isolation rules
Get-NetFirewallRule -DisplayName "Salt-GUI Isolation*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Allow Salt ports (4505, 4506) to/from master
New-NetFirewallRule -DisplayName "Salt-GUI Isolation - Salt Inbound 4505" `
    -Direction Inbound -RemoteAddress $SaltMasterIP -LocalPort 4505 -Protocol TCP -Action Allow | Out-Null

New-NetFirewallRule -DisplayName "Salt-GUI Isolation - Salt Inbound 4506" `
    -Direction Inbound -RemoteAddress $SaltMasterIP -LocalPort 4506 -Protocol TCP -Action Allow | Out-Null

New-NetFirewallRule -DisplayName "Salt-GUI Isolation - Salt Outbound 4505" `
    -Direction Outbound -RemoteAddress $SaltMasterIP -RemotePort 4505 -Protocol TCP -Action Allow | Out-Null

New-NetFirewallRule -DisplayName "Salt-GUI Isolation - Salt Outbound 4506" `
    -Direction Outbound -RemoteAddress $SaltMasterIP -RemotePort 4506 -Protocol TCP -Action Allow | Out-Null

# Allow DNS (needed for Salt in some configs)
New-NetFirewallRule -DisplayName "Salt-GUI Isolation - DNS Outbound" `
    -Direction Outbound -RemotePort 53 -Protocol UDP -Action Allow | Out-Null

Write-Host "Salt master ($SaltMasterIP) communication rules created"

Write-Host "`n[4/5] STOPPING POTENTIALLY EXPLOITED SERVICES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$servicesToStop = @(
    "TermService",      # Remote Desktop
    "W3SVC",           # IIS Web Server
    "MSSQLSERVER",     # SQL Server
    "FTPSVC",          # FTP
    "TlntSvr",         # Telnet
    "RemoteRegistry",  # Remote Registry
    "WinRM"            # Windows Remote Management (if not using)
)

foreach ($svc in $servicesToStop) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped: $svc"
        }
    } catch {
        # Service doesn't exist, skip
    }
}

Write-Host "`n[5/5] DISCONNECTING ACTIVE SESSIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    # Log off all RDP sessions
    $sessions = qwinsta 2>$null | Select-String "rdp-tcp" | ForEach-Object {
        $parts = $_.ToString().Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
        if ($parts[2] -match "^\d+$") { $parts[2] }
    }
    foreach ($sessionId in $sessions) {
        logoff $sessionId /server:localhost 2>$null
        Write-Host "Logged off session: $sessionId"
    }
} catch {
    Write-Host "No RDP sessions to disconnect"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "HOST ISOLATION COMPLETE" -ForegroundColor Cyan
Write-Host "Only Salt master ($SaltMasterIP) can communicate with this host" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
