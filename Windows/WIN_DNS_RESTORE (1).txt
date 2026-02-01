<#
.SYNOPSIS
    Restores DNS zones and records from a JSON backup.

.DESCRIPTION
    Reads a DNS backup created by DNS-Backup.ps1 and
    restores zones and records safely.
#>

param (
    [Parameter(Mandatory)]
    [string]$BackupFile,

    [string]$DnsServer = "localhost"
)

Write-Host "Starting DNS restore from:" -ForegroundColor Cyan
Write-Host "  $BackupFile" -ForegroundColor Gray

if (-not (Test-Path $BackupFile)) {
    Write-Host "Backup file not found." -ForegroundColor Red
    exit 1
}

if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "DnsServer module not found. Aborting." -ForegroundColor Red
    exit 1
}

Import-Module DnsServer

$data = Get-Content $BackupFile -Raw | ConvertFrom-Json

foreach ($zone in $data) {
    Write-Host "`nProcessing zone: $($zone.ZoneName)" -ForegroundColor Yellow

    # Create zone if missing
    if (-not (Get-DnsServerZone -ComputerName $DnsServer -Name $zone.ZoneName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating zone $($zone.ZoneName)" -ForegroundColor Cyan

        Add-DnsServerPrimaryZone `
            -ComputerName $DnsServer `
            -Name $zone.ZoneName `
            -ReplicationScope "Domain"
    } else {
        Write-Host "Zone already exists, skipping creation." -ForegroundColor Gray
    }

    # Restore records
    foreach ($record in $zone.Records) {
        try {
            Add-DnsServerResourceRecord `
                -ComputerName $DnsServer `
                -ZoneName $zone.ZoneName `
                -InputObject $record `
                -ErrorAction Stop
        } catch {
            Write-Host "Skipped existing or invalid record: $($record.HostName)" -ForegroundColor DarkGray
        }
    }
}

Write-Host "`nDNS restore completed." -ForegroundColor Green
