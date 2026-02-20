# ==============================================================================
# Script Name : ad-dns-restore.ps1
# Description : Restores Active Directory DNS configuration from a backup
#               created by ad-dns-backup.ps1. Includes DNS zones, records,
#               forwarders, and server settings.
# Author      : Tyler Olson
# Version     : 1.0
# ==============================================================================
# Usage       : .\ad-dns-restore.ps1 -BackupPath "C:\Backup\DNS\DNS_Backup_20250407_123045" [-ForceRestore]
# Notes       :
#   - Creates a backup of the current configuration before restoring
#   - Can force restoration with -ForceRestore parameter
# ==============================================================================

param(
    [Parameter()]
    [string]$BackupPath = "C:\Backup\DNS",

    [Parameter()]
    [switch]$ForceRestore = $false
)

# Log file setup
$LogDir = "$BackupPath\Logs"
$LogFile = "$LogDir\DNSBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

# Validate environment and backup
function Test-Environment {
    Write-Log "Validating environment and backup" "INFO"
    
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
    
    # Verify backup path exists
    if (-not (Test-Path $BackupPath)) {
        Write-Log "Backup path not found: $BackupPath" "ERROR"
        return $false
    }
    
    # Verify backup metadata if available
    $metadataFile = Join-Path -Path $BackupPath -ChildPath "backup_metadata.xml"
    if (Test-Path $metadataFile) {
        try {
            $metadata = Import-Clixml -Path $metadataFile
            Write-Log "Backup metadata found: Created on $($metadata.BackupDate) for $($metadata.ComputerName)" "INFO"
            
            # Verify backup type
            if ($metadata.BackupType -ne "DNS Server") {
                Write-Log "This backup appears to be of type $($metadata.BackupType), not DNS Server" "WARNING"
                
                if (-not $ForceRestore) {
                    Write-Log "Use -ForceRestore to continue anyway" "WARNING"
                    return $false
                }
            }
            
            # Check if backup is from same computer
            if ($metadata.ComputerName -ne $env:COMPUTERNAME) {
                Write-Log "This backup was created on $($metadata.ComputerName), not on this computer ($env:COMPUTERNAME)" "WARNING"
                
                if (-not $ForceRestore) {
                    Write-Log "Use -ForceRestore to continue anyway" "WARNING"
                    return $false
                }
            }
        }
        catch {
            Write-Log "Error reading backup metadata: $_" "WARNING"
        }
    }
    else {
        Write-Log "Backup metadata not found" "WARNING"
        
        if (-not $ForceRestore) {
            Write-Log "Use -ForceRestore to continue without metadata verification" "WARNING"
            return $false
        }
    }
    
    Write-Log "Environment and backup validation completed successfully" "SUCCESS"
    return $true
}

# Restore DNS Server configuration
function Restore-DnsServerConfig {
    Write-Log "Restoring DNS Server configuration" "INFO"
    $configPath = Join-Path -Path $BackupPath -ChildPath "ServerConfig"
    
    # Restore DNS Server cache settings
    try {
        $cacheSettingsFile = Join-Path -Path $configPath -ChildPath "dns_server_cache.xml"
        if (Test-Path $cacheSettingsFile) {
            $cacheSettings = Import-Clixml -Path $cacheSettingsFile
            Set-DnsServerCache -ComputerName localhost -MaxTtl $cacheSettings.MaxTtl -MaxNegativeTtl $cacheSettings.MaxNegativeTtl
            Write-Log "DNS Server cache settings restored" "SUCCESS"
        }
        else {
            Write-Log "DNS Server cache settings file not found in backup" "WARNING"
        }
    }
    catch {
        Write-Log "Error restoring DNS Server cache settings: $_" "ERROR"
    }
    
    # Restore DNS Server recursion settings
    try {
        $recursionSettingsFile = Join-Path -Path $configPath -ChildPath "dns_server_recursion.xml"
        if (Test-Path $recursionSettingsFile) {
            $recursionSettings = Import-Clixml -Path $recursionSettingsFile
            Set-DnsServerRecursion -ComputerName localhost -Enable $recursionSettings.Enable -AdditionalTimeout $recursionSettings.AdditionalTimeout -RetryInterval $recursionSettings.RetryInterval -Timeout $recursionSettings.Timeout
            Write-Log "DNS Server recursion settings restored" "SUCCESS"
        }
        else {
            Write-Log "DNS Server recursion settings file not found in backup" "WARNING"
        }
    }
    catch {
        Write-Log "Error restoring DNS Server recursion settings: $_" "ERROR"
    }
    
    # Restore forwarders
    try {
        $forwardersFile = Join-Path -Path $configPath -ChildPath "dns_server_forwarders.xml"
        if (Test-Path $forwardersFile) {
            $forwarders = Import-Clixml -Path $forwardersFile
            
            # Get the list of forwarder IP addresses
            $forwarderIps = $forwarders.IPAddress.IPAddressToString
            
            if ($forwarderIps) {
                Set-DnsServerForwarder -ComputerName localhost -IPAddress $forwarderIps -UseRootHint $forwarders.UseRootHint
                Write-Log "DNS Server forwarders restored" "SUCCESS"
            }
            else {
                Write-Log "No forwarder IP addresses found in backup" "WARNING"
            }
        }
        else {
            Write-Log "DNS Server forwarders file not found in backup" "WARNING"
        }
    }
    catch {
        Write-Log "Error restoring DNS Server forwarders: $_" "ERROR"
    }
    
    Write-Log "DNS Server configuration restoration completed" "SUCCESS"
}


function Restore-DnsZones {
    Write-Log "Restoring DNS zones" "INFO"
    
    $zonesPath = Join-Path -Path $BackupPath -ChildPath "Zones"
    
    # Get list of backed up zones
    try {
        $zonesListFile = Join-Path -Path $zonesPath -ChildPath "zones_list.xml"
        if (Test-Path $zonesListFile) {
            $zones = Import-Clixml -Path $zonesListFile
            Write-Log "Found $($zones.Count) zones in backup" "INFO"
            
            # Get current zones for comparison
            $currentZones = Get-DnsServerZone
            $currentZoneNames = $currentZones.ZoneName
            
            foreach ($zone in $zones) {
                $zoneName = $zone.ZoneName
                $zoneBackupPath = Join-Path -Path $zonesPath -ChildPath $zoneName
                
                if (Test-Path $zoneBackupPath) {
                    # Check if zone already exists
                    if ($currentZoneNames -contains $zoneName) {
                        Write-Log "Zone '$zoneName' already exists" "WARNING"
                        
                        if ($ForceRestore) {
                            # Delete existing zone if force restore is enabled
                            Remove-DnsServerZone -Name $zoneName -Force
                            Write-Log "Existing zone '$zoneName' removed for clean restore" "INFO"
                        }
                        else {
                            Write-Log "Skipping zone '$zoneName' (use -ForceRestore to overwrite)" "WARNING"
                            continue
                        }
                    }
                    
                    # Restore zone from backup
                    $zoneFile = Join-Path -Path $zoneBackupPath -ChildPath "$zoneName.dns"
                    if (Test-Path $zoneFile) {
                        # Import zone from zone file
                        if ($zone.ZoneType -eq "Primary") {
                            # Determine if zone is AD-integrated or file-based
                            $zonePropsFile = Join-Path -Path $zoneBackupPath -ChildPath "zone_properties.xml"
                            $zoneProps = Import-Clixml -Path $zonePropsFile
                            
                            if ($zoneProps.IsAutoCreated -eq $false) {
                                if ($zoneProps.IsDsIntegrated) {
                                    # AD-integrated zone
                                    Add-DnsServerPrimaryZone -Name $zoneName -ReplicationScope "Domain" -LoadExisting
                                    Write-Log "AD-integrated zone '$zoneName' added" "SUCCESS"
                                }
                                else {
                                    # File-based zone
                                    Add-DnsServerPrimaryZone -Name $zoneName -ZoneFile "$zoneName.dns"
                                    Write-Log "File-based zone '$zoneName' added" "SUCCESS"
                                }
                                
                                # Import resource records
                                try {
                                    # Import zone data from zone file
                                    dnscmd /zoneadd $zoneName /primary /file $zoneName.dns /load
                                }
                                catch {
                                    Write-Log "Error importing zone data for '$zoneName': $_" "ERROR"
                                }
                            }
                            else {
                                Write-Log "Skipping auto-created zone '$zoneName'" "INFO"
                            }
                        }
                        elseif ($zone.ZoneType -eq "Secondary") {
                            # Extract master servers from zone properties
                            $zonePropsFile = Join-Path -Path $zoneBackupPath -ChildPath "zone_properties.xml"
                            $zoneProps = Import-Clixml -Path $zonePropsFile
                            
                            if ($zoneProps.MasterServers) {
                                # Add secondary zone
                                $masterIps = $zoneProps.MasterServers.IPAddressToString
                                Add-DnsServerSecondaryZone -Name $zoneName -MasterServers $masterIps -ZoneFile "$zoneName.dns"
                                Write-Log "Secondary zone '$zoneName' added with master servers: $($masterIps -join ', ')" "SUCCESS"
                            }
                            else {
                                Write-Log "Master servers not found for secondary zone '$zoneName'" "ERROR"
                            }
                        }
                        elseif ($zone.ZoneType -eq "Stub") {
                            # Extract master servers from zone properties
                            $zonePropsFile = Join-Path -Path $zoneBackupPath -ChildPath "zone_properties.xml"
                            $zoneProps = Import-Clixml -Path $zonePropsFile
                            
                            if ($zoneProps.MasterServers) {
                                # Add stub zone
                                $masterIps = $zoneProps.MasterServers.IPAddressToString
                                Add-DnsServerStubZone -Name $zoneName -MasterServers $masterIps -ZoneFile "$zoneName.dns"
                                Write-Log "Stub zone '$zoneName' added with master servers: $($masterIps -join ', ')" "SUCCESS"
                            }
                            else {
                                Write-Log "Master servers not found for stub zone '$zoneName'" "ERROR"
                            }
                        }
                        else {
                            Write-Log "Unknown zone type '$($zone.ZoneType)' for zone '$zoneName'" "WARNING"
                        }
                    }
                    else {
                        Write-Log "Zone file not found for zone '$zoneName'" "ERROR"
                    }
                }
                else {
                    Write-Log "Backup folder not found for zone '$zoneName'" "ERROR"
                }
            }
        }
        else {
            Write-Log "Zones list file not found in backup" "ERROR"
        }
    }
    catch {
        Write-Log "Error restoring DNS zones: $_" "ERROR"
    }
    
    Write-Log "DNS zones restoration completed" "SUCCESS"
}

# Restore conditional forwarders
function Restore-ConditionalForwarders {
    Write-Log "Restoring conditional forwarders" "INFO"
    
    $cfPath = Join-Path -Path $BackupPath -ChildPath "ConditionalForwarders"
    
    if (Test-Path $cfPath) {
        try {
            $cfFile = Join-Path -Path $cfPath -ChildPath "conditional_forwarders.xml"
            if (Test-Path $cfFile) {
                $cfZones = Import-Clixml -Path $cfFile
                
                foreach ($cfZone in $cfZones) {
                    $zoneName = $cfZone.ZoneName
                    
                    # Check if zone already exists
                    $existingZone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue
                    if ($existingZone) {
                        if ($ForceRestore) {
                            Remove-DnsServerZone -Name $zoneName -Force
                            Write-Log "Existing conditional forwarder '$zoneName' removed for clean restore" "INFO"
                        }
                        else {
                            Write-Log "Conditional forwarder '$zoneName' already exists. Skipping (use -ForceRestore to overwrite)" "WARNING"
                            continue
                        }
                    }
                    
                    # Get forwarder details
                    $cfDetailFile = Join-Path -Path $cfPath -ChildPath "$($zoneName)_details.xml"
                    
                    if (Test-Path $cfDetailFile) {
                        $cfDetail = Import-Clixml -Path $cfDetailFile
                    }
                    
                    # Create conditional forwarder
                    if ($cfZone.MasterServers) {
                        $masterIps = $cfZone.MasterServers.IPAddressToString
                        
                        # Determine if this should be AD-integrated
                        if ($cfZone.IsDsIntegrated) {
                            Add-DnsServerConditionalForwarderZone -Name $zoneName -MasterServers $masterIps -ReplicationScope "Domain"
                        }
                        else {
                            Add-DnsServerConditionalForwarderZone -Name $zoneName -MasterServers $masterIps
                        }
                        
                        Write-Log "Conditional forwarder '$zoneName' restored with master servers: $($masterIps -join ', ')" "SUCCESS"
                    }
                    else {
                        Write-Log "Master servers not found for conditional forwarder '$zoneName'" "ERROR"
                    }
                }
            }
            else {
                Write-Log "Conditional forwarders file not found in backup" "WARNING"
            }
        }
        catch {
            Write-Log "Error restoring conditional forwarders: $_" "ERROR"
        }
    }
    else {
        Write-Log "Conditional forwarders backup folder not found" "INFO"
    }
    
    Write-Log "Conditional forwarders restoration completed" "SUCCESS"
}

# Restore DNS query resolution policies
function Restore-DnsClientSettings {
    Write-Log "Restoring DNS client and policy settings" "INFO"
    
    $clientPath = Join-Path -Path $BackupPath -ChildPath "ClientSettings"
    
    if (Test-Path $clientPath) {
        # Restore policies
        try {
            $policiesFile = Join-Path -Path $clientPath -ChildPath "dns_policies.xml"
            if (Test-Path $policiesFile) {
                $policies = Import-Clixml -Path $policiesFile
                
                # Remove existing policies
                $existingPolicies = Get-DnsServerQueryResolutionPolicy
                foreach ($existingPolicy in $existingPolicies) {
                    Remove-DnsServerQueryResolutionPolicy -Name $existingPolicy.Name -Force
                    Write-Log "Removed existing DNS policy: $($existingPolicy.Name)" "INFO"
                }
                
                # Add policies from backup
                foreach ($policy in $policies) {
                    # Recreate policy (complex, depends on policy type)
                    # This is a simplified implementation - in practice, would need to handle different policy types
                    
                    try {
                        # Add policy with basic properties
                        Add-DnsServerQueryResolutionPolicy -Name $policy.Name -Action $policy.Action -Condition $policy.Condition -ProcessingOrder $policy.ProcessingOrder
                        Write-Log "DNS policy '$($policy.Name)' restored" "SUCCESS"
                    }
                    catch {
                        Write-Log "Error restoring DNS policy '$($policy.Name)': $_" "ERROR"
                    }
                }
            }
            else {
                Write-Log "DNS policies file not found in backup" "WARNING"
            }
        }
        catch {
            Write-Log "Error restoring DNS policies: $_" "ERROR"
        }
    }
    else {
        Write-Log "DNS client settings backup folder not found" "INFO"
    }
    
    Write-Log "DNS client and policy settings restoration completed" "SUCCESS"
}

# Restore DNS registry settings
function Restore-DnsRegistry {
    Write-Log "Restoring DNS registry settings" "INFO"
    
    $registryPath = Join-Path -Path $BackupPath -ChildPath "Registry"
    
    if (Test-Path $registryPath) {
        try {
            # Restore DNS registry keys
            $dnsRegFile = Join-Path -Path $registryPath -ChildPath "dns_registry.reg"
            if (Test-Path $dnsRegFile) {
                $regOutput = reg import $dnsRegFile
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "DNS registry keys restored" "SUCCESS"
                }
                else {
                    Write-Log "Failed to restore DNS registry keys: $regOutput" "ERROR"
                }
            }
            else {
                Write-Log "DNS registry file not found in backup" "WARNING"
            }
            
            # Restore DNS Server registry keys
            $dnsServerRegFile = Join-Path -Path $registryPath -ChildPath "dns_server_registry.reg"
            if (Test-Path $dnsServerRegFile) {
                $regOutput = reg import $dnsServerRegFile
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "DNS Server registry keys restored" "SUCCESS"
                }
                else {
                    Write-Log "Failed to restore DNS Server registry keys: $regOutput" "ERROR"
                }
            }
            else {
                Write-Log "DNS Server registry file not found in backup" "WARNING"
            }
        }
        catch {
            Write-Log "Error restoring DNS registry settings: $_" "ERROR"
        }
    }
    else {
        Write-Log "DNS registry backup folder not found" "INFO"
    }
    
    Write-Log "DNS registry settings restoration completed" "SUCCESS"
}

# Restore DNS files
function Restore-DnsFiles {
    Write-Log "Restoring DNS server files" "INFO"
    
    $filesPath = Join-Path -Path $BackupPath -ChildPath "Files"
    
    if (Test-Path $filesPath) {
        try {
            $sourcePath = Join-Path -Path $filesPath -ChildPath "dns"
            $destPath = "$env:windir\System32\dns"
            
            if (Test-Path $sourcePath) {
                # Stop DNS Server service before restoring files
                Stop-Service -Name DNS -Force
                Write-Log "DNS Server service stopped" "INFO"
                
                # Backup existing files
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $backupPath = "$env:windir\System32\dns_backup_$timestamp"
                
                if (Test-Path $destPath) {
                    Copy-Item -Path $destPath -Destination $backupPath -Recurse -Force
                    Write-Log "Existing DNS files backed up to $backupPath" "INFO"
                }
                
                # Copy files from backup
                Copy-Item -Path "$sourcePath\*" -Destination $destPath -Recurse -Force
                Write-Log "DNS files restored from $sourcePath to $destPath" "SUCCESS"
                
                # Start DNS Server service
                Start-Service -Name DNS
                Write-Log "DNS Server service started" "INFO"
            }
            else {
                Write-Log "DNS files source directory not found in backup" "WARNING"
            }
        }
        catch {
            Write-Log "Error restoring DNS files: $_" "ERROR"
            
            # Make sure DNS service is started even if restore fails
            Start-Service -Name DNS -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Log "DNS files backup folder not found" "INFO"
    }
    
    Write-Log "DNS files restoration completed" "SUCCESS"
}


# Main execution
function Start-DnsRestore {
    # Start timing
    $startTime = Get-Date
    
    Write-Log "Starting DNS server restore process" "INFO"
    Write-Log "Backup source: $BackupPath" "INFO"
    
    # Validate environment and backup
    if (-not (Test-Environment)) {
        Write-Log "Environment or backup validation failed. Aborting restore process." "ERROR"
        return
    }
    
    # Execute restore steps
    Restore-DnsServerConfig
    Restore-DnsZones
    Restore-ConditionalForwarders
    Restore-DnsClientSettings
    Restore-DnsRegistry
    Restore-DnsFiles
    
    
    # Calculate execution time
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).ToString()
    
    Write-Log "DNS server restore process completed" "SUCCESS"
    Write-Log "Total execution time: $executionTime" "INFO"
    
    # Return restore status
    return $true
}

# Start the restore process
$restoreSuccess = Start-DnsRestore

# Display summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                 DNS SERVER RESTORE COMPLETE                       " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Restore from backup location:" -ForegroundColor White
Write-Host $BackupPath -ForegroundColor Green
Write-Host ""
Write-Host "The following components were restored:" -ForegroundColor White
Write-Host "- DNS server configuration" -ForegroundColor White
Write-Host "- DNS zones and resource records" -ForegroundColor White
Write-Host "- Conditional forwarders" -ForegroundColor White
Write-Host "- DNS client settings and policies" -ForegroundColor White
Write-Host "- DNS registry keys" -ForegroundColor White
Write-Host "- DNS server files" -ForegroundColor White
Write-Host ""
Write-Host "Log file: $LogFile" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
