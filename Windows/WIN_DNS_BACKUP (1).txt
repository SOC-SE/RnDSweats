<#
.SYNOPSIS
    Backs up DNS zones and records to JSON.

.DESCRIPTION
    Exports all DNS zones and their resource records
    from a Windows DNS Server using the DnsServer module.
#>

param (
    [string]$DnsServer = "localhost",
    [string]$BackupDir = "C:\DNS-Backups"
)

# Ensure backup directory exists
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

$timestamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
$backupFile = Join-Path $BackupDir "DNSBackup_$timestamp.json"

Write-Host "Starting DNS backup from $DnsServer" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "DnsServer module not found. Aborting." -ForegroundColor Red
    exit 1
}

Import-Module DnsServer

$backup = @()

$zones = Get-DnsServerZone -ComputerName $DnsServer

foreach ($zone in $zones) {
    Write-Host "Backing up zone: $($zone.ZoneName)" -ForegroundColor Yellow

    $records = Get-DnsServerResourceRecord `
        -ComputerName $DnsServer `
        -ZoneName $zone.ZoneName

    $backup += [PSCustomObject]@{
        ZoneName = $zone.ZoneName
        ZoneType = $zone.ZoneType
        IsDsIntegrated = $zone.IsDsIntegrated
        Records = $records
    }
}

$backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8

Write-Host "DNS backup completed:" -ForegroundColor Green
Write-Host "  $backupFile" -ForegroundColor Gray
