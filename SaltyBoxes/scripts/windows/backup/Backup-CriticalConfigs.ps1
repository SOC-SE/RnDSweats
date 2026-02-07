# ==============================================================================
# Backup Critical Configs - Windows
# Create backups of critical system configurations before making changes
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [string]$BackupDir = "C:\Backups"
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupPath = Join-Path $BackupDir "backup_${env:COMPUTERNAME}_$Timestamp"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONFIG BACKUP - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Backup Path: $BackupPath" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create backup directory
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null

Write-Host "`n[1/8] BACKING UP LOCAL USERS AND GROUPS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$UsersPath = Join-Path $BackupPath "users"
New-Item -ItemType Directory -Path $UsersPath -Force | Out-Null

Get-LocalUser | Export-Csv "$UsersPath\local_users.csv" -NoTypeInformation
Write-Host "  Backed up: Local users"

Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    try {
        Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{Group=$group; Member=$_.Name; Type=$_.ObjectClass}
        }
    } catch {}
} | Export-Csv "$UsersPath\group_memberships.csv" -NoTypeInformation
Write-Host "  Backed up: Group memberships"

Write-Host "`n[2/8] BACKING UP REGISTRY KEYS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$RegPath = Join-Path $BackupPath "registry"
New-Item -ItemType Directory -Path $RegPath -Force | Out-Null

$regKeys = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM\SYSTEM\CurrentControlSet\Services",
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
)

foreach ($key in $regKeys) {
    $safeName = $key -replace "\\", "_" -replace ":", ""
    try {
        reg export $key "$RegPath\$safeName.reg" /y 2>$null
        Write-Host "  Backed up: $key"
    } catch {
        Write-Host "  Skipped: $key (not accessible)" -ForegroundColor Yellow
    }
}

Write-Host "`n[3/8] BACKING UP FIREWALL RULES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$FwPath = Join-Path $BackupPath "firewall"
New-Item -ItemType Directory -Path $FwPath -Force | Out-Null

netsh advfirewall export "$FwPath\firewall_policy.wfw" | Out-Null
Write-Host "  Backed up: Firewall policy"

Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action, Profile |
    Export-Csv "$FwPath\firewall_rules.csv" -NoTypeInformation
Write-Host "  Backed up: Firewall rules list"

Write-Host "`n[4/8] BACKING UP SCHEDULED TASKS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$TasksPath = Join-Path $BackupPath "tasks"
New-Item -ItemType Directory -Path $TasksPath -Force | Out-Null

Get-ScheduledTask | ForEach-Object {
    $taskName = $_.TaskName -replace '[\\/:*?"<>|]', '_'
    try {
        Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath 2>$null |
            Out-File "$TasksPath\$taskName.xml" -ErrorAction SilentlyContinue
    } catch {}
}
Write-Host "  Backed up: Scheduled tasks"

Write-Host "`n[5/8] BACKING UP SERVICES CONFIGURATION" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$SvcPath = Join-Path $BackupPath "services"
New-Item -ItemType Directory -Path $SvcPath -Force | Out-Null

Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Export-Csv "$SvcPath\services.csv" -NoTypeInformation
Write-Host "  Backed up: Services configuration"

Write-Host "`n[6/8] BACKING UP HOSTS FILE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$NetPath = Join-Path $BackupPath "network"
New-Item -ItemType Directory -Path $NetPath -Force | Out-Null

Copy-Item "C:\Windows\System32\drivers\etc\hosts" "$NetPath\hosts" -ErrorAction SilentlyContinue
Write-Host "  Backed up: hosts file"

Get-DnsClientServerAddress | Export-Csv "$NetPath\dns_servers.csv" -NoTypeInformation
Write-Host "  Backed up: DNS configuration"

Get-NetIPConfiguration | Out-File "$NetPath\ip_configuration.txt"
Write-Host "  Backed up: IP configuration"

Write-Host "`n[7/8] BACKING UP IIS CONFIGURATION (if present)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$IISPath = Join-Path $BackupPath "iis"
if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
    New-Item -ItemType Directory -Path $IISPath -Force | Out-Null
    try {
        Copy-Item "C:\Windows\System32\inetsrv\config\applicationHost.config" "$IISPath\" -ErrorAction SilentlyContinue
        Write-Host "  Backed up: IIS configuration"
    } catch {
        Write-Host "  IIS config not accessible" -ForegroundColor Yellow
    }
} else {
    Write-Host "  IIS not installed, skipping"
}

Write-Host "`n[8/8] BACKING UP AUDIT POLICY" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$AuditPath = Join-Path $BackupPath "audit"
New-Item -ItemType Directory -Path $AuditPath -Force | Out-Null

auditpol /backup /file:"$AuditPath\audit_policy.csv" 2>$null
Write-Host "  Backed up: Audit policy"

secedit /export /cfg "$AuditPath\security_policy.inf" 2>$null
Write-Host "  Backed up: Security policy"

# Create zip archive
Write-Host "`n----------------------------------------"
Write-Host "Creating compressed archive..."
$ZipPath = "$BackupPath.zip"
Compress-Archive -Path $BackupPath -DestinationPath $ZipPath -Force
Remove-Item -Path $BackupPath -Recurse -Force

$BackupSize = (Get-Item $ZipPath).Length / 1MB

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "BACKUP COMPLETE" -ForegroundColor Green
Write-Host "Archive: $ZipPath" -ForegroundColor Green
Write-Host "Size: $([math]::Round($BackupSize, 2)) MB" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "BACKUP_FILE=$ZipPath"
