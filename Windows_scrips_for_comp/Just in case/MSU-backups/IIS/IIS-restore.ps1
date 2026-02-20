# ==============================================================================
# Script Name : IIS-restore.ps1
# Description : Restores IIS (Internet Information Services) configuration
#               from a backup created by IIS-backup.ps1
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.0 - Initial Release
# ==============================================================================
# Usage       : .\IIS-restore.ps1 -BackupPath <path to backup folder>
# Notes       :
#   - Must be run with administrative privileges on an IIS server
#   - Requires the backup folder created by IIS-backup.ps1
# ==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath
)

# Log file setup
$LogDir = "$BackupPath\Logs"
$LogFile = "$LogDir\IISRestore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create log directory if it doesn't exist
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

    # Check if backup path exists
    if (-not (Test-Path $BackupPath)) {
        Write-Log "Backup path does not exist: $BackupPath" "ERROR"
        return $false
    }

    # Check if IIS is installed
    $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
    if (-not $iisFeature.Installed) {
        Write-Log "IIS (Web-Server) feature is not installed" "ERROR"
        return $false
    }

    # Check if needed modules are available
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Write-Log "WebAdministration module loaded successfully" "SUCCESS"
    }
    catch {
        Write-Log "Failed to load WebAdministration module: $_" "ERROR"
        return $false
    }

    Write-Log "Environment validation completed successfully" "SUCCESS"
    return $true
}

# Restore IIS configuration files
function Restore-IISConfiguration {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring IIS configuration files" "INFO"

    $configBackupPath = "$BackupFolder\Configuration"
    if (-not (Test-Path $configBackupPath)) {
        Write-Log "Configuration backup folder not found: $configBackupPath" "ERROR"
        return
    }

    try {
        # Stop IIS before restoring configuration
        Write-Log "Stopping IIS services" "INFO"
        Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
        Stop-Service WAS -Force -ErrorAction SilentlyContinue

        # Restore applicationHost.config
        $appHostConfig = "$configBackupPath\applicationHost.config"
        if (Test-Path $appHostConfig) {
            $destPath = "$env:windir\System32\inetsrv\config\applicationHost.config"
            Copy-Item -Path $appHostConfig -Destination $destPath -Force
            Write-Log "applicationHost.config restored successfully" "SUCCESS"
        }

        # Restore administration.config
        $adminConfig = "$configBackupPath\administration.config"
        if (Test-Path $adminConfig) {
            $destPath = "$env:windir\System32\inetsrv\config\administration.config"
            Copy-Item -Path $adminConfig -Destination $destPath -Force
            Write-Log "administration.config restored successfully" "SUCCESS"
        }

        # Restore redirection.config if exists
        $redirectConfig = "$configBackupPath\redirection.config"
        if (Test-Path $redirectConfig) {
            $destPath = "$env:windir\System32\inetsrv\config\redirection.config"
            Copy-Item -Path $redirectConfig -Destination $destPath -Force
            Write-Log "redirection.config restored successfully" "SUCCESS"
        }

        # Start IIS services
        Write-Log "Starting IIS services" "INFO"
        Start-Service W3SVC -ErrorAction SilentlyContinue
        Start-Service WAS -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Failed to restore IIS configuration files: $_" "ERROR"
    }

    Write-Log "IIS configuration files restore completed" "SUCCESS"
}

# Restore application pools
function Restore-AppPools {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring IIS application pools" "INFO"

    $appPoolsBackupPath = "$BackupFolder\ApplicationPools"
    if (-not (Test-Path $appPoolsBackupPath)) {
        Write-Log "Application pools backup folder not found: $appPoolsBackupPath" "WARNING"
        return
    }

    try {
        # Get all backed up app pool files
        $appPoolFiles = Get-ChildItem -Path $appPoolsBackupPath -Filter "*.xml" | Where-Object { $_.Name -ne "apppools_list.xml" }

        foreach ($appPoolFile in $appPoolFiles) {
            try {
                $appPool = Import-Clixml -Path $appPoolFile.FullName
                $appPoolName = $appPool.Name

                # Check if app pool already exists
                if (Test-Path "IIS:\AppPools\$appPoolName") {
                    Write-Log "Application pool '$appPoolName' already exists, skipping" "INFO"
                    continue
                }

                # Create new app pool
                New-WebAppPool -Name $appPoolName -Force

                # Restore app pool properties
                $appPoolPath = "IIS:\AppPools\$appPoolName"
                Set-ItemProperty -Path $appPoolPath -Name "managedRuntimeVersion" -Value $appPool.managedRuntimeVersion -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $appPoolPath -Name "managedPipelineMode" -Value $appPool.managedPipelineMode -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $appPoolPath -Name "startMode" -Value $appPool.startMode -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $appPoolPath -Name "autoStart" -Value $appPool.autoStart -ErrorAction SilentlyContinue

                Write-Log "Application pool '$appPoolName' restored successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to restore application pool from $($appPoolFile.Name): $_" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error during application pools restore: $_" "ERROR"
    }

    Write-Log "Application pools restore completed" "SUCCESS"
}

# Restore websites
function Restore-WebSites {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring IIS websites" "INFO"

    $sitesBackupPath = "$BackupFolder\WebSites"
    if (-not (Test-Path $sitesBackupPath)) {
        Write-Log "Websites backup folder not found: $sitesBackupPath" "WARNING"
        return
    }

    try {
        # Get all site directories
        $siteDirs = Get-ChildItem -Path $sitesBackupPath -Directory

        foreach ($siteDir in $siteDirs) {
            try {
                $siteConfigFile = "$($siteDir.FullName)\site_config.xml"
                if (-not (Test-Path $siteConfigFile)) {
                    Write-Log "Site config not found for $($siteDir.Name)" "WARNING"
                    continue
                }

                $site = Import-Clixml -Path $siteConfigFile
                $siteName = $site.Name

                # Check if site already exists
                if (Get-Website -Name $siteName -ErrorAction SilentlyContinue) {
                    Write-Log "Website '$siteName' already exists, skipping" "INFO"
                    continue
                }

                # Create the website
                $physicalPath = $site.physicalPath
                if ($physicalPath) {
                    $physicalPath = [System.Environment]::ExpandEnvironmentVariables($physicalPath)
                }

                # Ensure physical path exists
                if ($physicalPath -and -not (Test-Path $physicalPath)) {
                    New-Item -Path $physicalPath -ItemType Directory -Force | Out-Null
                    Write-Log "Created physical path for site '$siteName': $physicalPath" "INFO"
                }

                # Create website
                New-Website -Name $siteName -PhysicalPath $physicalPath -ApplicationPool $site.applicationPool -Force

                # Restore bindings
                $bindingsFile = "$($siteDir.FullName)\bindings.xml"
                if (Test-Path $bindingsFile) {
                    $bindings = Import-Clixml -Path $bindingsFile

                    # Remove default binding
                    Get-WebBinding -Name $siteName | Remove-WebBinding -ErrorAction SilentlyContinue

                    # Add backed up bindings
                    foreach ($binding in $bindings) {
                        try {
                            New-WebBinding -Name $siteName -Protocol $binding.protocol -Port $binding.bindingInformation.Split(':')[1] -IPAddress $binding.bindingInformation.Split(':')[0] -HostHeader $binding.bindingInformation.Split(':')[2] -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Log "Failed to restore binding for '$siteName': $_" "WARNING"
                        }
                    }
                }

                # Set site state
                if ($site.state -eq "Started") {
                    Start-Website -Name $siteName -ErrorAction SilentlyContinue
                }
                else {
                    Stop-Website -Name $siteName -ErrorAction SilentlyContinue
                }

                Write-Log "Website '$siteName' restored successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to restore website from $($siteDir.Name): $_" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error during websites restore: $_" "ERROR"
    }

    Write-Log "Websites restore completed" "SUCCESS"
}

# Restore IIS registry keys
function Restore-IISRegistry {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring IIS registry keys" "INFO"

    $registryBackupPath = "$BackupFolder\Registry"
    if (-not (Test-Path $registryBackupPath)) {
        Write-Log "Registry backup folder not found: $registryBackupPath" "WARNING"
        return
    }

    try {
        # Import IIS registry keys
        $iisRegFile = "$registryBackupPath\iis_registry.reg"
        if (Test-Path $iisRegFile) {
            reg import $iisRegFile

            if ($LASTEXITCODE -eq 0) {
                Write-Log "IIS registry keys imported from $iisRegFile" "SUCCESS"
            }
            else {
                Write-Log "Failed to import IIS registry keys" "ERROR"
            }
        }

        # Import W3SVC registry keys
        $w3svcRegFile = "$registryBackupPath\w3svc_registry.reg"
        if (Test-Path $w3svcRegFile) {
            reg import $w3svcRegFile

            if ($LASTEXITCODE -eq 0) {
                Write-Log "W3SVC registry keys imported from $w3svcRegFile" "SUCCESS"
            }
            else {
                Write-Log "Failed to import W3SVC registry keys" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error during IIS registry restore: $_" "ERROR"
    }

    Write-Log "IIS registry restore completed" "SUCCESS"
}

# Restore SSL certificates information
function Restore-SSLCertificates {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring SSL certificate bindings information" "INFO"

    $sslBackupPath = "$BackupFolder\SSL"
    if (-not (Test-Path $sslBackupPath)) {
        Write-Log "SSL backup folder not found: $sslBackupPath" "WARNING"
        return
    }

    try {
        $certInfoFile = "$sslBackupPath\certificate_info.xml"
        if (Test-Path $certInfoFile) {
            $certInfo = Import-Clixml -Path $certInfoFile

            Write-Log "SSL certificate information loaded from backup" "INFO"
            Write-Log "Note: You will need to manually rebind SSL certificates using the following information:" "WARNING"

            foreach ($cert in $certInfo) {
                Write-Log "  Site: $($cert.SiteName), Binding: $($cert.Binding), Certificate Hash: $($cert.CertificateHash)" "INFO"
            }
        }
    }
    catch {
        Write-Log "Error during SSL certificates restore: $_" "ERROR"
    }

    Write-Log "SSL certificates information restore completed" "SUCCESS"
}

# Main execution
function Start-IISRestore {
    # Start timing
    $startTime = Get-Date

    Write-Log "Starting IIS server restore process" "INFO"
    Write-Log "Restore source: $BackupPath" "INFO"

    # Validate environment
    if (-not (Test-Environment)) {
        Write-Log "Environment validation failed. Aborting restore process." "ERROR"
        return
    }

    # Confirm with user before proceeding
    Write-Host ""
    Write-Host "WARNING: This will restore IIS configuration from the backup." -ForegroundColor Yellow
    Write-Host "Current IIS configuration may be overwritten." -ForegroundColor Yellow
    Write-Host ""
    $confirmation = Read-Host "Do you want to continue? (yes/no)"

    if ($confirmation -ne "yes") {
        Write-Log "Restore cancelled by user" "WARNING"
        return
    }

    # Execute restore steps
    Restore-IISConfiguration -BackupFolder $BackupPath
    Restore-AppPools -BackupFolder $BackupPath
    Restore-WebSites -BackupFolder $BackupPath
    Restore-IISRegistry -BackupFolder $BackupPath
    Restore-SSLCertificates -BackupFolder $BackupPath

    # Calculate execution time
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).ToString()

    Write-Log "IIS server restore process completed" "SUCCESS"
    Write-Log "Total execution time: $executionTime" "INFO"
}

# Start the restore process
Start-IISRestore

# Display summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                 IIS SERVER RESTORE COMPLETE                     " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "The restore included:" -ForegroundColor White
Write-Host "- IIS configuration files (applicationHost.config, etc.)" -ForegroundColor White
Write-Host "- Application pools" -ForegroundColor White
Write-Host "- Websites and bindings" -ForegroundColor White
Write-Host "- IIS registry keys" -ForegroundColor White
Write-Host ""
Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "- SSL certificates need to be manually rebound (see log for details)" -ForegroundColor Yellow
Write-Host "- Verify website physical paths exist and have correct permissions" -ForegroundColor Yellow
Write-Host "- Test all websites and applications after restore" -ForegroundColor Yellow
Write-Host ""
Write-Host "Log file: $LogFile" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
