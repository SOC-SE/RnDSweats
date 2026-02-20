# ==============================================================================
# Script Name : ad-dns-backup.ps1
# Description : Backs up Active Directory DNS configuration 
#               created by ad-dns-backup.ps1. Includes DNS zones, records,
#               forwarders, and server settings.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.2 - Code Review 07/23/25
# ==============================================================================
# Usage       : .\ad-dns-backup.ps1 [backup path] [compress?]
# Notes       :
#   - Must be run with administrative privileges on a Domain Controller
#   - this backs up a shit load, I love backing up.
# ==============================================================================

param(
    [Parameter()]
    [string]$BackupPath = "C:\Backup\DNS",
    
    [Parameter()]
    [switch]$Compress = $true
)

# Log file setup
$LogDir = "$BackupPath\Logs"
$LogFile = "$LogDir\DNSBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create directories if they don't exist
if (-not (Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

# Function for logging
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$Level] $Message"
    $LogMessage | Out-File -FilePath $LogFile -Append
    
    # Also output to console with color coding
    switch ($Level) {
        "INFO" { Write-Host $LogMessage -ForegroundColor Gray }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
}

# Validate environment
function Test-Environment {
    Write-Log "Validating environment" "INFO"
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Script must be run as Administrator" "ERROR"
        return $false
    }
    
    # Check if this is a Domain Controller
    $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    if (-not $isDC) {
        Write-Log "Script must be run on a Domain Controller" "ERROR"
        return $false
    }
    
    # Check if DNS Server feature is installed
    $dnsServer = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue
    if (-not $dnsServer.Installed) {
        Write-Log "DNS Server feature is not installed" "ERROR"
        return $false
    }
    
    # Check if needed modules are available
    try {
        Import-Module DnsServer -ErrorAction Stop
        Write-Log "DNS Server module loaded successfully" "SUCCESS"
    }
    catch {
        Write-Log "Failed to load DNS Server module: $_" "ERROR"
        return $false
    }
    
    Write-Log "Environment validation completed successfully" "SUCCESS"
    return $true
}

# Backup DNS Server configuration
function Backup-DnsServerConfig {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up DNS Server configuration" "INFO"

    $configBackupPath = "$BackupFolder\ServerConfig"
    if (-not (Test-Path $configBackupPath)) {
        New-Item -Path $configBackupPath -ItemType Directory -Force | Out-Null
    }
    
    # Export DNS Server settings
    try {
        $serverConfigFile = "$configBackupPath\dns_server_settings.xml"
        Get-DnsServerSetting -All | Export-Clixml -Path $serverConfigFile
        Write-Log "DNS Server settings exported to $serverConfigFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server settings: $_" "ERROR"
    }
    
    # Export DNS Server diagnostics
    try {
        $diagnosticsFile = "$configBackupPath\dns_server_diagnostics.xml"
        Get-DnsServerDiagnostics | Export-Clixml -Path $diagnosticsFile
        Write-Log "DNS Server diagnostics exported to $diagnosticsFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server diagnostics: $_" "ERROR"
    }
    
    # Export DNS Server scavenging settings
    try {
        $scavengingFile = "$configBackupPath\dns_server_scavenging.xml"
        Get-DnsServerScavenging | Export-Clixml -Path $scavengingFile
        Write-Log "DNS Server scavenging settings exported to $scavengingFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server scavenging settings: $_" "ERROR"
    }
    
    # Export DNS Server global query block list
    try {
        $globalBlockListFile = "$configBackupPath\dns_server_globalqueryblacklist.xml"
        Get-DnsServerGlobalQueryBlockList | Export-Clixml -Path $globalBlockListFile
        Write-Log "DNS Server global query block list exported to $globalBlockListFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server global query block list: $_" "ERROR"
    }
    
    # Export DNS Server cache settings
    try {
        $cacheSettingsFile = "$configBackupPath\dns_server_cache.xml"
        Get-DnsServerCache | Export-Clixml -Path $cacheSettingsFile
        Write-Log "DNS Server cache settings exported to $cacheSettingsFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server cache settings: $_" "ERROR"
    }
    
    # Export DNS Server recursion settings
    try {
        $recursionSettingsFile = "$configBackupPath\dns_server_recursion.xml"
        Get-DnsServerRecursion | Export-Clixml -Path $recursionSettingsFile
        Write-Log "DNS Server recursion settings exported to $recursionSettingsFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server recursion settings: $_" "ERROR"
    }
    
    # Export forwarders
    try {
        $forwardersFile = "$configBackupPath\dns_server_forwarders.xml"
        Get-DnsServerForwarder | Export-Clixml -Path $forwardersFile
        Write-Log "DNS Server forwarders exported to $forwardersFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS Server forwarders: $_" "ERROR"
    }
    
    Write-Log "DNS Server configuration backup completed" "SUCCESS"
}

# Backup DNS zones
function Backup-DnsZones {
    param (
        [string]$BackupFolder
    )
    
    Write-Log "Backing up DNS zones" "INFO"
    
    # Directory verification
    $zonesBackupPath = "$BackupFolder\Zones"
    if (-not (Test-Path $zonesBackupPath)) {
        New-Item -Path $zonesBackupPath -ItemType Directory -Force | Out-Null
    }
    
    # Export list of zones
    try {
        $zonesListFile = "$zonesBackupPath\zones_list.xml"
        Get-DnsServerZone | Export-Clixml -Path $zonesListFile
        Write-Log "DNS zones list exported to $zonesListFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to export DNS zones list: $_" "ERROR"
    }
    
    # Export each zone to a zone file
    try {
        $zones = Get-DnsServerZone
        foreach ($zone in $zones) {
            $zoneName = $zone.ZoneName
            $zoneBackupPath = "$zonesBackupPath\$zoneName"
            
            if (-not (Test-Path $zoneBackupPath)) {
                New-Item -Path $zoneBackupPath -ItemType Directory -Force | Out-Null
            }
            
            # Export zone properties
            $zonePropsFile = "$zoneBackupPath\zone_properties.xml"
            $zone | Export-Clixml -Path $zonePropsFile
            
            # Export zone as a zone file
            $zoneFile = "$zoneBackupPath\$zoneName.dns"
            
            if ($zone.ZoneType -ne "Stub") {
                $relativeZoneFile = "$zoneName.backup.dns"
                Export-DnsServerZone -Name $zoneName -FileName $relativeZoneFile
                Write-Log "Zone '$zoneName' exported to $relativeZoneFile" "SUCCESS"
            }
            else {
                Write-Log "Skipping export of stub zone '$zoneName'" "INFO"
            }
            
            # Export resource records
            $rrBackupPath = "$zoneBackupPath\ResourceRecords"
            if (-not (Test-Path $rrBackupPath)) {
                New-Item -Path $rrBackupPath -ItemType Directory -Force | Out-Null
            }
            
            # Get all records for this zone
            $rrFile = "$rrBackupPath\resource_records.xml"
            Get-DnsServerResourceRecord -ZoneName $zoneName | Export-Clixml -Path $rrFile
            Write-Log "Resource records for zone '$zoneName' exported to $rrFile" "SUCCESS"
        }
    }
    catch {
        Write-Log "Error during zone export (AD integrated zones hate this, manually export and import): $_" "ERROR" 
    }
    
    Write-Log "DNS zones backup completed" "SUCCESS"
}

# Backup DNS conditional forwarders
function Backup-ConditionalForwarders {
    param (
        [string]$BackupFolder
    )
    
    Write-Log "Backing up DNS conditional forwarders" "INFO"
    
    $cfBackupPath = "$BackupFolder\ConditionalForwarders"
    if (-not (Test-Path $cfBackupPath)) {
        New-Item -Path $cfBackupPath -ItemType Directory -Force | Out-Null
    }
    
    try {
        $cfZones = Get-DnsServerZone | Where-Object { $_.ZoneType -eq "Forwarder" }
        
        if ($cfZones) {
            $cfFile = "$cfBackupPath\conditional_forwarders.xml"
            $cfZones | Export-Clixml -Path $cfFile
            Write-Log "Conditional forwarders exported to $cfFile" "SUCCESS"
            
            foreach ($cfZone in $cfZones) {
                $cfDetail = Get-DnsServerZoneTransferPolicy -ZoneName $cfZone.ZoneName
                if ($cfDetail) {
                    $cfDetailFile = "$cfBackupPath\$($cfZone.ZoneName)_details.xml"
                    $cfDetail | Export-Clixml -Path $cfDetailFile
                }
            }
        }
        else {
            Write-Log "No conditional forwarders found" "INFO"
        }
    }
    catch {
        Write-Log "Error during conditional forwarders backup: $_" "ERROR"
    }
    
    Write-Log "Conditional forwarders backup completed" "SUCCESS"
}

# Backup DNS query resolution policies
function Backup-DnsClientSettings {
    param (
        [string]$BackupFolder
    )
    
    Write-Log "Backing up DNS client settings" "INFO"
    
    $clientBackupPath = "$BackupFolder\ClientSettings"
    if (-not (Test-Path $clientBackupPath)) {
        New-Item -Path $clientBackupPath -ItemType Directory -Force | Out-Null
    }
    
    try {
        # Export DNS client settings
        $clientSettingsFile = "$clientBackupPath\dns_client_settings.txt"
        ipconfig /all > $clientSettingsFile
        Write-Log "DNS client settings exported to $clientSettingsFile" "SUCCESS"
        
        # Export policies
        try {
            $policiesFile = "$clientBackupPath\dns_policies.xml"
            Get-DnsServerQueryResolutionPolicy | Export-Clixml -Path $policiesFile
            Write-Log "DNS policies exported to $policiesFile" "SUCCESS"
        }
        catch {
            Write-Log "Failed to export DNS policies: $_" "WARNING"
        }
    }
    catch {
        Write-Log "Error during DNS client settings backup: $_" "ERROR"
    }
    
    Write-Log "DNS client settings backup completed" "SUCCESS"
}

# Copy registry DNS keys
function Backup-DnsRegistry {
    param (
        [string]$BackupFolder
    )
    
    Write-Log "Backing up DNS registry keys" "INFO"
    
    $registryBackupPath = "$BackupFolder\Registry"
    if (-not (Test-Path $registryBackupPath)) {
        New-Item -Path $registryBackupPath -ItemType Directory -Force | Out-Null
    }
    
    try {
        # Export DNS registry keys
        $dnsRegFile = "$registryBackupPath\dns_registry.reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Services\DNS" $dnsRegFile /y
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "DNS registry keys exported to $dnsRegFile" "SUCCESS"
        }
        else {
            Write-Log "Failed to export DNS registry keys" "ERROR"
        }
        
        # Export DNS Server registry keys
        $dnsServerRegFile = "$registryBackupPath\dns_server_registry.reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Services\DNSCache" $dnsServerRegFile /y
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "DNS Server registry keys exported to $dnsServerRegFile" "SUCCESS"
        }
        else {
            Write-Log "Failed to export DNS Server registry keys" "ERROR"
        }
    }
    catch {
        Write-Log "Error during DNS registry backup: $_" "ERROR"
    }
    
    Write-Log "DNS registry backup completed" "SUCCESS"
}

# Copy DNS service files
function Backup-DnsFiles {
    param (
        [string]$BackupFolder
    )
    
    Write-Log "Backing up DNS server files" "INFO"
    
    $filesBackupPath = "$BackupFolder\Files"
    if (-not (Test-Path $filesBackupPath)) {
        New-Item -Path $filesBackupPath -ItemType Directory -Force | Out-Null
    }
    
    try {
        # Copy DNS server files (typically in %windir%\System32\dns)
        $sourcePath = "$env:windir\System32\dns"
        $destPath = "$filesBackupPath\dns"
        
        if (Test-Path $sourcePath) {
            # Create destination if it doesn't exist
            if (-not (Test-Path $destPath)) {
                New-Item -Path $destPath -ItemType Directory -Force | Out-Null
            }
            
            # Copy files
            Copy-Item -Path "$sourcePath\*" -Destination $destPath -Recurse -Force
            Write-Log "DNS server files copied from $sourcePath to $destPath" "SUCCESS"
        }
        else {
            Write-Log "DNS server files directory not found at $sourcePath" "WARNING"
        }
    }
    catch {
        Write-Log "Error during DNS files backup: $_" "ERROR"
    }
    
    Write-Log "DNS files backup completed" "SUCCESS"
}

# Create final backup package
function Create-BackupPackage {
    param (
        [string]$BackupFolder,
        [bool]$CreateCompressedArchive
    )
    
    Write-Log "Creating final backup package" "INFO"
    
    try {
        # Create metadata file
        $metadataFile = "$BackupFolder\backup_metadata.xml"
        $metadata = @{
            BackupDate = Get-Date
            ComputerName = $env:COMPUTERNAME
            DomainName = (Get-ADDomain).DNSRoot
            BackupType = "DNS Server"
            Creator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        }
        
        $metadata | Export-Clixml -Path $metadataFile
        Write-Log "Backup metadata created at $metadataFile" "SUCCESS"
        
        # Compress the backup if requested
        if ($CreateCompressedArchive) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $archiveName = "$BackupFolder\..\DNS_Backup_$timestamp.zip"
            
            # Compress using .NET's built-in compression
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($BackupFolder, $archiveName)
            
            if (Test-Path $archiveName) {
                Write-Log "Compressed backup created at $archiveName" "SUCCESS"
                
                # Optional: Remove the original folder after successful compression
                # Remove-Item -Path $BackupFolder -Recurse -Force
            }
            else {
                Write-Log "Failed to create compressed backup" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error creating backup package: $_" "ERROR"
    }
    
    Write-Log "Backup package creation completed" "SUCCESS"
}

# Main execution
function Start-DnsBackup {
    # Start timing
    $startTime = Get-Date
    
    Write-Log "Starting DNS server backup process" "INFO"
    Write-Log "Backup destination: $BackupPath" "INFO"
    
    # Create timestamp-based backup folder
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFolder = "$BackupPath\DNS_Backup_$timestamp"
    
    if (-not (Test-Path $backupFolder)) {
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    }
    
    # Validate environment
    if (-not (Test-Environment)) {
        Write-Log "Environment validation failed. Aborting backup process." "ERROR"
        return
    }
    
    # Execute backup steps
    Backup-DnsServerConfig -BackupFolder $backupFolder
    Backup-DnsZones -BackupFolder $backupFolder
    Backup-ConditionalForwarders -BackupFolder $backupFolder
    Backup-DnsClientSettings -BackupFolder $backupFolder
    Backup-DnsRegistry -BackupFolder $backupFolder
    Backup-DnsFiles -BackupFolder $backupFolder
    
    # Create final package
    Create-BackupPackage -BackupFolder $backupFolder -CreateCompressedArchive $Compress
    
    # Calculate execution time
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).ToString()
    
    Write-Log "DNS server backup process completed" "SUCCESS"
    Write-Log "Total execution time: $executionTime" "INFO"
    
    # Return backup location
    return $backupFolder
}

# Start the backup process
$backupLocation = Start-DnsBackup

# Display summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                 DNS SERVER BACKUP COMPLETE                       " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Backup was created at:" -ForegroundColor White
Write-Host $backupLocation -ForegroundColor Green
Write-Host ""
Write-Host "The backup includes:" -ForegroundColor White
Write-Host "- DNS server configuration" -ForegroundColor White
Write-Host "- DNS zones and resource records" -ForegroundColor White
Write-Host "- Conditional forwarders" -ForegroundColor White
Write-Host "- DNS client settings and policies" -ForegroundColor White
Write-Host "- DNS registry keys" -ForegroundColor White
Write-Host "- DNS server files" -ForegroundColor White
Write-Host ""
Write-Host "Log file: $LogFile" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
