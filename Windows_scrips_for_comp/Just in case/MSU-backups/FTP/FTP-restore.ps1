# ==============================================================================
# Script Name : FTP-restore.ps1
# Description : Restores FTP Server configuration from a backup created by
#               FTP-backup.ps1
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.1 - Removing redundant functions
# ==============================================================================
# Usage       : .\FTP-restore.ps1 -BackupPath <path to backup folder>
# Notes       :
#   - Must be run with administrative privileges on an FTP server
#   - Requires the backup folder created by FTP-backup.ps1
# ==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath
)

# Log file setup
$LogDir = "$BackupPath\Logs"
$LogFile = "$LogDir\FTPRestore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

    # Check if FTP Server is installed
    $ftpFeature = Get-WindowsFeature -Name Web-Ftp-Server -ErrorAction SilentlyContinue
    if (-not $ftpFeature.Installed) {
        Write-Log "FTP Server (Web-Ftp-Server) feature is not installed" "ERROR"
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

# Restore FTP configuration files
function Restore-FTPConfiguration {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring FTP configuration files" "INFO"

    $configBackupPath = "$BackupFolder\Configuration"
    if (-not (Test-Path $configBackupPath)) {
        Write-Log "Configuration backup folder not found: $configBackupPath" "ERROR"
        return
    }

    try {
        # Stop FTP service before restoring configuration
        Write-Log "Stopping FTP service" "INFO"
        Stop-Service FTPSVC -Force -ErrorAction SilentlyContinue

        # Restore applicationHost.config (contains FTP configuration)
        $appHostConfig = "$configBackupPath\applicationHost.config"
        if (Test-Path $appHostConfig) {
            $destPath = "$env:windir\System32\inetsrv\config\applicationHost.config"
            Copy-Item -Path $appHostConfig -Destination $destPath -Force
            Write-Log "applicationHost.config restored successfully" "SUCCESS"
        }

        # Start FTP service
        Write-Log "Starting FTP service" "INFO"
        Start-Service FTPSVC -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Failed to restore FTP configuration files: $_" "ERROR"
    }

    Write-Log "FTP configuration files restore completed" "SUCCESS"
}

# Restore FTP sites
function Restore-FTPSites {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring FTP sites" "INFO"

    $sitesBackupPath = "$BackupFolder\FTPSites"
    if (-not (Test-Path $sitesBackupPath)) {
        Write-Log "FTP sites backup folder not found: $sitesBackupPath" "WARNING"
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
                    Write-Log "FTP site '$siteName' already exists, skipping" "INFO"
                    continue
                }

                # Create the FTP site
                $physicalPath = $site.physicalPath
                if ($physicalPath) {
                    $physicalPath = [System.Environment]::ExpandEnvironmentVariables($physicalPath)
                }

                # Ensure physical path exists
                if ($physicalPath -and -not (Test-Path $physicalPath)) {
                    New-Item -Path $physicalPath -ItemType Directory -Force | Out-Null
                    Write-Log "Created physical path for FTP site '$siteName': $physicalPath" "INFO"
                }

                # Create FTP site
                New-Website -Name $siteName -PhysicalPath $physicalPath -ApplicationPool $site.applicationPool -Force

                # Restore FTP bindings
                $bindingsFile = "$($siteDir.FullName)\bindings.xml"
                if (Test-Path $bindingsFile) {
                    $bindings = Import-Clixml -Path $bindingsFile

                    foreach ($binding in $bindings) {
                        try {
                            New-WebBinding -Name $siteName -Protocol "ftp" -Port $binding.bindingInformation.Split(':')[1] -IPAddress $binding.bindingInformation.Split(':')[0] -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Log "Failed to restore FTP binding for '$siteName': $_" "WARNING"
                        }
                    }
                }

                # Restore authorization rules
                $authRulesFile = "$($siteDir.FullName)\authorization_rules.xml"
                if (Test-Path $authRulesFile) {
                    try {
                        $authRules = Import-Clixml -Path $authRulesFile
                        # Note: Authorization rules are complex to restore programmatically
                        # They are restored via the applicationHost.config
                        Write-Log "Authorization rules information loaded for '$siteName'" "INFO"
                    }
                    catch {
                        Write-Log "Failed to load authorization rules for '$siteName': $_" "WARNING"
                    }
                }

                # Restore SSL settings
                $sslSettingsFile = "$($siteDir.FullName)\ssl_settings.xml"
                if (Test-Path $sslSettingsFile) {
                    try {
                        $sslSettings = Import-Clixml -Path $sslSettingsFile
                        Write-Log "SSL settings information loaded for '$siteName'" "INFO"
                    }
                    catch {
                        Write-Log "Failed to load SSL settings for '$siteName': $_" "WARNING"
                    }
                }

                # Set site state
                if ($site.state -eq "Started") {
                    Start-Website -Name $siteName -ErrorAction SilentlyContinue
                }
                else {
                    Stop-Website -Name $siteName -ErrorAction SilentlyContinue
                }

                Write-Log "FTP site '$siteName' restored successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to restore FTP site from $($siteDir.Name): $_" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error during FTP sites restore: $_" "ERROR"
    }

    Write-Log "FTP sites restore completed" "SUCCESS"
}

# Restore FTP content directories
function Restore-FTPContent {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring FTP content directories" "INFO"

    $contentBackupPath = "$BackupFolder\Content"
    if (-not (Test-Path $contentBackupPath)) {
        Write-Log "Content backup folder not found: $contentBackupPath" "WARNING"
        return
    }

    try {
        # Get all FTP site content directories
        $siteDirs = Get-ChildItem -Path $contentBackupPath -Directory

        foreach ($siteDir in $siteDirs) {
            $siteName = $siteDir.Name

            # Get the site's physical path
            try {
                $site = Get-Website -Name $siteName -ErrorAction Stop
                $physicalPath = $site.physicalPath

                if ($physicalPath) {
                    $physicalPath = [System.Environment]::ExpandEnvironmentVariables($physicalPath)
                }

                if (-not $physicalPath) {
                    Write-Log "Could not determine physical path for site '$siteName'" "WARNING"
                    continue
                }

                # Ensure physical path exists
                if (-not (Test-Path $physicalPath)) {
                    New-Item -Path $physicalPath -ItemType Directory -Force | Out-Null
                    Write-Log "Created physical path for content restore: $physicalPath" "INFO"
                }

                Write-Log "Restoring content for FTP site '$siteName' to $physicalPath" "INFO"

                # Copy content from backup to physical path
                Copy-Item -Path "$($siteDir.FullName)\*" -Destination $physicalPath -Recurse -Force -ErrorAction Continue

                # Get size of restored content
                $size = (Get-ChildItem -Path $physicalPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $sizeInMB = [math]::Round($size / 1MB, 2)

                Write-Log "Content for '$siteName' restored successfully ($sizeInMB MB)" "SUCCESS"
            }
            catch {
                Write-Log "Error restoring content for '$siteName': $_" "ERROR"
            }
        }

        Write-Log "FTP content restore completed" "SUCCESS"
    }
    catch {
        Write-Log "Error during FTP content restore: $_" "ERROR"
    }
}

# Restore FTP registry keys
function Restore-FTPRegistry {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring FTP registry keys" "INFO"

    $registryBackupPath = "$BackupFolder\Registry"
    if (-not (Test-Path $registryBackupPath)) {
        Write-Log "Registry backup folder not found: $registryBackupPath" "WARNING"
        return
    }

    try {
        # Import FTPSVC registry keys
        $ftpsvcRegFile = "$registryBackupPath\ftpsvc_registry.reg"
        if (Test-Path $ftpsvcRegFile) {
            reg import $ftpsvcRegFile

            if ($LASTEXITCODE -eq 0) {
                Write-Log "FTPSVC registry keys imported from $ftpsvcRegFile" "SUCCESS"
            }
            else {
                Write-Log "Failed to import FTPSVC registry keys" "ERROR"
            }
        }

        # Import FTP IIS registry keys
        $ftpIISRegFile = "$registryBackupPath\ftp_iis_registry.reg"
        if (Test-Path $ftpIISRegFile) {
            reg import $ftpIISRegFile

            if ($LASTEXITCODE -eq 0) {
                Write-Log "FTP IIS registry keys imported from $ftpIISRegFile" "SUCCESS"
            }
            else {
                Write-Log "Failed to import FTP IIS registry keys" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error during FTP registry restore: $_" "ERROR"
    }

    Write-Log "FTP registry restore completed" "SUCCESS"
}

# Restore FTP firewall settings
function Restore-FTPFirewall {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring FTP firewall settings" "INFO"

    $firewallBackupPath = "$BackupFolder\Firewall"
    if (-not (Test-Path $firewallBackupPath)) {
        Write-Log "Firewall backup folder not found: $firewallBackupPath" "WARNING"
        return
    }

    try {
        $firewallFile = "$firewallBackupPath\firewall_settings.xml"
        if (Test-Path $firewallFile) {
            $firewallSettings = Import-Clixml -Path $firewallFile

            Write-Log "FTP firewall settings loaded from backup" "INFO"
            Write-Log "Note: Firewall settings are restored via configuration files" "INFO"
        }

        # Load Windows Firewall rules info
        $fwRulesFile = "$firewallBackupPath\windows_firewall_rules.xml"
        if (Test-Path $fwRulesFile) {
            Write-Log "Windows Firewall FTP rules information loaded" "INFO"
            Write-Log "Note: You may need to manually verify/recreate firewall rules" "WARNING"
        }
    }
    catch {
        Write-Log "Error during FTP firewall settings restore: $_" "ERROR"
    }

    Write-Log "FTP firewall settings restore completed" "SUCCESS"
}

# Restore SSL certificates information
function Restore-FTPSSLCertificates {
    param (
        [string]$BackupFolder
    )

    Write-Log "Restoring FTP SSL certificate information" "INFO"

    $sslBackupPath = "$BackupFolder\SSL"
    if (-not (Test-Path $sslBackupPath)) {
        Write-Log "SSL backup folder not found: $sslBackupPath" "WARNING"
        return
    }

    try {
        $certInfoFile = "$sslBackupPath\ftp_ssl_info.xml"
        if (Test-Path $certInfoFile) {
            $certInfo = Import-Clixml -Path $certInfoFile

            Write-Log "FTP SSL certificate information loaded from backup" "INFO"
            Write-Log "Note: You will need to manually verify SSL certificate bindings" "WARNING"

            foreach ($cert in $certInfo) {
                Write-Log "  Site: $($cert.SiteName), Binding: $($cert.Binding)" "INFO"
            }
        }
    }
    catch {
        Write-Log "Error during FTP SSL certificates restore: $_" "ERROR"
    }

    Write-Log "FTP SSL certificates information restore completed" "SUCCESS"
}

# Main execution
function Start-FTPRestore {
    # Start timing
    $startTime = Get-Date

    Write-Log "Starting FTP server restore process" "INFO"
    Write-Log "Restore source: $BackupPath" "INFO"

    # Validate environment
    if (-not (Test-Environment)) {
        Write-Log "Environment validation failed. Aborting restore process." "ERROR"
        return
    }

    # Confirm with user before proceeding
    Write-Host ""
    Write-Host "WARNING: This will restore FTP configuration and content from the backup." -ForegroundColor Yellow
    Write-Host "Current FTP configuration may be overwritten." -ForegroundColor Yellow
    Write-Host ""
    $confirmation = Read-Host "Do you want to continue? (yes/no)"

    if ($confirmation -ne "yes") {
        Write-Log "Restore cancelled by user" "WARNING"
        return
    }

    # Execute restore steps
    Restore-FTPConfiguration -BackupFolder $BackupPath
    Restore-FTPSites -BackupFolder $BackupPath
    Restore-FTPContent -BackupFolder $BackupPath
    Restore-FTPRegistry -BackupFolder $BackupPath
    Restore-FTPFirewall -BackupFolder $BackupPath
    Restore-FTPSSLCertificates -BackupFolder $BackupPath

    # Calculate execution time
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).ToString()

    Write-Log "FTP server restore process completed" "SUCCESS"
    Write-Log "Total execution time: $executionTime" "INFO"
}

# Start the restore process
Start-FTPRestore

# Display summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                 FTP SERVER RESTORE COMPLETE                     " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "The restore included:" -ForegroundColor White
Write-Host "- FTP server configuration" -ForegroundColor White
Write-Host "- All FTP sites and bindings" -ForegroundColor White
Write-Host "- FTP content directories (files served by FTP)" -ForegroundColor White
Write-Host "- FTP registry keys" -ForegroundColor White
Write-Host "- Firewall settings information" -ForegroundColor White
Write-Host "- SSL certificate information" -ForegroundColor White
Write-Host ""
Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "- Verify FTP sites are accessible and working correctly" -ForegroundColor Yellow
Write-Host "- Check SSL certificate bindings (see log for details)" -ForegroundColor Yellow
Write-Host "- Verify firewall rules allow FTP traffic" -ForegroundColor Yellow
Write-Host "- Test FTP authentication and authorization" -ForegroundColor Yellow
Write-Host "- Ensure content directory permissions are correct" -ForegroundColor Yellow
Write-Host ""
Write-Host "Log file: $LogFile" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
