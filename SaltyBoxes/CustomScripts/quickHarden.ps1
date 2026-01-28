# ==============================================================================
# Quick Harden - Windows
# Fast security hardening for competition
# REQUIRES ADMIN - Makes system changes!
# ==============================================================================

#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "QUICK HARDEN - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] ENABLING WINDOWS FIREWALL (All Profiles)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
Write-Host "Firewall enabled, default inbound: BLOCK" -ForegroundColor Green

Write-Host "`n[2/12] ALLOWING ESSENTIAL SERVICES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
# Allow RDP (if needed)
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
# Allow WinRM for Salt
New-NetFirewallRule -DisplayName "Salt-WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Allow -ErrorAction SilentlyContinue
# Allow Salt minion ports
New-NetFirewallRule -DisplayName "Salt-Minion" -Direction Outbound -Protocol TCP -RemotePort 4505,4506 -Action Allow -ErrorAction SilentlyContinue
Write-Host "Essential firewall rules added" -ForegroundColor Green

Write-Host "`n[3/12] DISABLING UNNECESSARY SERVICES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$servicesToDisable = @(
    "RemoteRegistry",      # Remote Registry
    "TlntSvr",            # Telnet
    "SNMP",               # SNMP
    "SSDPSRV",            # SSDP Discovery
    "upnphost",           # UPnP Host
    "WinHttpAutoProxySvc" # WinHTTP AutoProxy
)
foreach ($svc in $servicesToDisable) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "Disabled: $svc" -ForegroundColor Green
    }
}

Write-Host "`n[4/12] CONFIGURING ACCOUNT POLICIES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
# Set account lockout
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
Write-Host "Account lockout: 5 attempts, 30 min lockout" -ForegroundColor Green

Write-Host "`n[5/12] DISABLING GUEST ACCOUNT" -ForegroundColor Yellow
Write-Host "----------------------------------------"
net user guest /active:no 2>$null
Write-Host "Guest account disabled" -ForegroundColor Green

Write-Host "`n[6/12] CONFIGURING AUDIT POLICY" -ForegroundColor Yellow
Write-Host "----------------------------------------"
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
Write-Host "Audit policies enabled" -ForegroundColor Green

Write-Host "`n[7/12] DISABLING SMBv1" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
Write-Host "SMBv1 disabled" -ForegroundColor Green

Write-Host "`n[8/12] ENABLING SMB SIGNING" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Write-Host "SMB signing required" -ForegroundColor Green

Write-Host "`n[9/12] DISABLING POWERSHELL V2" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$psV2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
if ($psV2Feature -and $psV2Feature.State -eq 'Enabled') {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue
    Write-Host "PowerShell v2 disabled" -ForegroundColor Green
} elseif (-not $psV2Feature) {
    Write-Host "PowerShell v2 feature not present on this system" -ForegroundColor Yellow
} else {
    Write-Host "PowerShell v2 already disabled" -ForegroundColor Green
}

Write-Host "`n[10/12] ENABLING POWERSHELL LOGGING" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1
Write-Host "PowerShell script block logging enabled" -ForegroundColor Green

Write-Host "`n[11/12] SECURING RDP" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2
Write-Host "RDP NLA and TLS required" -ForegroundColor Green

Write-Host "`n[12/12] CHECKING LOCAL ADMINISTRATORS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
Write-Host "Local Administrators:"
$admins | ForEach-Object { Write-Host "  - $($_.Name)" }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "QUICK HARDEN COMPLETE" -ForegroundColor Cyan
Write-Host "Review output and test services!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
