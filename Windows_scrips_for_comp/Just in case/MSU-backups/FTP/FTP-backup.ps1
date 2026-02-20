# ==============================================================================
# Script Name : FTP-backup.ps1
# Description : Backs up FTP Server configuration including FTP sites,
#               authorization rules, SSL settings, firewall configuration,
#               and user isolation settings.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.0 
# ==============================================================================
# Usage       : .\FTP-backup.ps1 [backup path] [compress?]
# Notes       :
#   - Must be run with administrative privileges on an FTP server
# ==============================================================================

param(
    [Parameter()]
    [string]$BackupPath = "C:\Backup\FTP",

    [Parameter()]
    [switch]$Compress = $true
)

# Log file setup
$LogDir = "$BackupPath\Logs"
$LogFile = "$LogDir\FTPBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

    # Check if FTP service is running
    $ftpService = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
    if ($ftpService) {
        if ($ftpService.Status -ne "Running") {
            Write-Log "FTP (FTPSVC) service is not running" "WARNING"
        }
    }
    else {
        Write-Log "FTP (FTPSVC) service not found" "ERROR"
        return $false
    }

    Write-Log "Environment validation completed successfully" "SUCCESS"
    return $true
}

# Backup FTP configuration files
function Backup-FTPConfiguration {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP configuration" "INFO"

    $configBackupPath = "$BackupFolder\Configuration"
    if (-not (Test-Path $configBackupPath)) {
        New-Item -Path $configBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Backup applicationHost.config (contains FTP configuration)
        $appHostConfig = "$env:windir\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $appHostConfig) {
            Copy-Item -Path $appHostConfig -Destination "$configBackupPath\applicationHost.config" -Force
            Write-Log "applicationHost.config backed up successfully" "SUCCESS"
        }

        # Export FTP server configuration using WebAdministration
        $ftpConfigFile = "$configBackupPath\ftp_server_config.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer" -Name "." | Export-Clixml -Path $ftpConfigFile
        Write-Log "FTP server configuration exported to $ftpConfigFile" "SUCCESS"

        # Export FTP global settings
        $ftpGlobalFile = "$configBackupPath\ftp_global_settings.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites" -Name "." | Export-Clixml -Path $ftpGlobalFile
        Write-Log "FTP global settings exported to $ftpGlobalFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to backup FTP configuration: $_" "ERROR"
    }

    Write-Log "FTP configuration backup completed" "SUCCESS"
}

# Backup FTP sites
function Backup-FTPSites {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP sites" "INFO"

    $sitesBackupPath = "$BackupFolder\FTPSites"
    if (-not (Test-Path $sitesBackupPath)) {
        New-Item -Path $sitesBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Get all sites and filter for FTP
        $allSites = Get-Website
        $ftpSites = @()

        foreach ($site in $allSites) {
            $ftpBinding = Get-WebBinding -Name $site.Name | Where-Object { $_.protocol -eq "ftp" }
            if ($ftpBinding) {
                $ftpSites += $site
            }
        }

        if ($ftpSites.Count -eq 0) {
            Write-Log "No FTP sites found" "WARNING"
            return
        }

        # Export FTP sites list
        $ftpSitesListFile = "$sitesBackupPath\ftp_sites_list.xml"
        $ftpSites | Export-Clixml -Path $ftpSitesListFile
        Write-Log "FTP sites list exported to $ftpSitesListFile" "SUCCESS"

        # Export each FTP site configuration
        foreach ($site in $ftpSites) {
            $siteName = $site.Name
            $siteBackupPath = "$sitesBackupPath\$siteName"

            if (-not (Test-Path $siteBackupPath)) {
                New-Item -Path $siteBackupPath -ItemType Directory -Force | Out-Null
            }

            # Export site configuration
            $siteConfigFile = "$siteBackupPath\site_config.xml"
            $site | Export-Clixml -Path $siteConfigFile
            Write-Log "FTP site '$siteName' configuration exported" "SUCCESS"

            # Export FTP bindings
            $bindingsFile = "$siteBackupPath\bindings.xml"
            Get-WebBinding -Name $siteName | Where-Object { $_.protocol -eq "ftp" } | Export-Clixml -Path $bindingsFile
            Write-Log "FTP bindings for '$siteName' exported" "SUCCESS"

            # Export FTP authorization rules
            try {
                $authRulesFile = "$siteBackupPath\authorization_rules.xml"
                Get-WebConfiguration -Filter "system.ftpServer/security/authorization" -PSPath "IIS:\Sites\$siteName" | Export-Clixml -Path $authRulesFile
                Write-Log "Authorization rules for '$siteName' exported" "SUCCESS"
            }
            catch {
                Write-Log "Failed to export authorization rules for '$siteName': $_" "WARNING"
            }

            # Export FTP SSL settings
            try {
                $sslSettingsFile = "$siteBackupPath\ssl_settings.xml"
                Get-WebConfiguration -Filter "system.ftpServer/security/ssl" -PSPath "IIS:\Sites\$siteName" | Export-Clixml -Path $sslSettingsFile
                Write-Log "SSL settings for '$siteName' exported" "SUCCESS"
            }
            catch {
                Write-Log "Failed to export SSL settings for '$siteName': $_" "WARNING"
            }

            # Export FTP user isolation settings
            try {
                $userIsolationFile = "$siteBackupPath\user_isolation.xml"
                Get-WebConfiguration -Filter "system.ftpServer/userIsolation" -PSPath "IIS:\Sites\$siteName" | Export-Clixml -Path $userIsolationFile
                Write-Log "User isolation settings for '$siteName' exported" "SUCCESS"
            }
            catch {
                Write-Log "Failed to export user isolation settings for '$siteName': $_" "WARNING"
            }

            # Export FTP directory browsing settings
            try {
                $dirBrowsingFile = "$siteBackupPath\directory_browsing.xml"
                Get-WebConfiguration -Filter "system.ftpServer/directoryBrowse" -PSPath "IIS:\Sites\$siteName" | Export-Clixml -Path $dirBrowsingFile
                Write-Log "Directory browsing settings for '$siteName' exported" "SUCCESS"
            }
            catch {
                Write-Log "Failed to export directory browsing settings for '$siteName': $_" "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error during FTP sites backup: $_" "ERROR"
    }

    Write-Log "FTP sites backup completed" "SUCCESS"
}

# Backup FTP firewall settings
function Backup-FTPFirewall {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP firewall settings" "INFO"

    $firewallBackupPath = "$BackupFolder\Firewall"
    if (-not (Test-Path $firewallBackupPath)) {
        New-Item -Path $firewallBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export FTP firewall settings
        $firewallFile = "$firewallBackupPath\firewall_settings.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/firewallSupport" -Name "." | Export-Clixml -Path $firewallFile
        Write-Log "FTP firewall settings exported to $firewallFile" "SUCCESS"

        # Export Windows Firewall rules for FTP
        try {
            $fwRulesFile = "$firewallBackupPath\windows_firewall_rules.xml"
            Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*FTP*" } | Export-Clixml -Path $fwRulesFile
            Write-Log "Windows Firewall FTP rules exported" "SUCCESS"
        }
        catch {
            Write-Log "Failed to export Windows Firewall rules: $_" "WARNING"
        }
    }
    catch {
        Write-Log "Error during FTP firewall settings backup: $_" "ERROR"
    }

    Write-Log "FTP firewall settings backup completed" "SUCCESS"
}

# Backup FTP authorization and authentication
function Backup-FTPSecurity {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP security settings" "INFO"

    $securityBackupPath = "$BackupFolder\Security"
    if (-not (Test-Path $securityBackupPath)) {
        New-Item -Path $securityBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export FTP authentication settings
        $authFile = "$securityBackupPath\authentication.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/security/authentication" -Name "." | Export-Clixml -Path $authFile
        Write-Log "FTP authentication settings exported" "SUCCESS"

        # Export global authorization settings
        $globalAuthFile = "$securityBackupPath\global_authorization.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/security/authorization" -Name "." | Export-Clixml -Path $globalAuthFile
        Write-Log "Global authorization settings exported" "SUCCESS"

        # Export command filtering settings
        try {
            $cmdFilterFile = "$securityBackupPath\command_filtering.xml"
            Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/security/commandFiltering" -Name "." | Export-Clixml -Path $cmdFilterFile
            Write-Log "Command filtering settings exported" "SUCCESS"
        }
        catch {
            Write-Log "Failed to export command filtering settings: $_" "WARNING"
        }

        # Export request filtering settings
        try {
            $reqFilterFile = "$securityBackupPath\request_filtering.xml"
            Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/security/requestFiltering" -Name "." | Export-Clixml -Path $reqFilterFile
            Write-Log "Request filtering settings exported" "SUCCESS"
        }
        catch {
            Write-Log "Failed to export request filtering settings: $_" "WARNING"
        }
    }
    catch {
        Write-Log "Error during FTP security settings backup: $_" "ERROR"
    }

    Write-Log "FTP security settings backup completed" "SUCCESS"
}

# Backup FTP SSL certificates
function Backup-FTPSSLCertificates {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP SSL certificate information" "INFO"

    $sslBackupPath = "$BackupFolder\SSL"
    if (-not (Test-Path $sslBackupPath)) {
        New-Item -Path $sslBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Get all sites with FTP bindings
        $allSites = Get-Website
        $certInfo = @()

        foreach ($site in $allSites) {
            $ftpBinding = Get-WebBinding -Name $site.Name | Where-Object { $_.protocol -eq "ftp" }

            if ($ftpBinding) {
                # Get SSL settings for this FTP site
                try {
                    $sslSettings = Get-WebConfiguration -Filter "system.ftpServer/security/ssl" -PSPath "IIS:\Sites\$($site.Name)"

                    if ($sslSettings) {
                        $certInfo += [PSCustomObject]@{
                            SiteName = $site.Name
                            SSLSettings = $sslSettings
                            Binding = $ftpBinding.bindingInformation
                        }
                    }
                }
                catch {
                    Write-Log "Failed to get SSL settings for site '$($site.Name)': $_" "WARNING"
                }
            }
        }

        if ($certInfo.Count -gt 0) {
            $certInfoFile = "$sslBackupPath\ftp_ssl_info.xml"
            $certInfo | Export-Clixml -Path $certInfoFile
            Write-Log "FTP SSL information exported" "SUCCESS"
        }
        else {
            Write-Log "No FTP SSL configurations found" "INFO"
        }

        # Note: Actual certificate private keys are not exported for security reasons
        Write-Log "Note: SSL certificate private keys are not included in backup for security" "INFO"
    }
    catch {
        Write-Log "Error during FTP SSL certificates backup: $_" "ERROR"
    }

    Write-Log "FTP SSL certificates backup completed" "SUCCESS"
}

# Backup FTP messages and logging
function Backup-FTPMessagesAndLogging {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP messages and logging settings" "INFO"

    $messagesBackupPath = "$BackupFolder\Messages"
    if (-not (Test-Path $messagesBackupPath)) {
        New-Item -Path $messagesBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export FTP messages
        $messagesFile = "$messagesBackupPath\ftp_messages.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/messages" -Name "." | Export-Clixml -Path $messagesFile
        Write-Log "FTP messages exported" "SUCCESS"

        # Export FTP logging settings
        $loggingFile = "$messagesBackupPath\logging_settings.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.ftpServer/log" -Name "." | Export-Clixml -Path $loggingFile
        Write-Log "FTP logging settings exported" "SUCCESS"

        # Export site-specific logging settings
        $allSites = Get-Website
        foreach ($site in $allSites) {
            $ftpBinding = Get-WebBinding -Name $site.Name | Where-Object { $_.protocol -eq "ftp" }

            if ($ftpBinding) {
                try {
                    $siteLoggingFile = "$messagesBackupPath\$($site.Name)_logging.xml"
                    Get-WebConfiguration -Filter "system.ftpServer/log" -PSPath "IIS:\Sites\$($site.Name)" | Export-Clixml -Path $siteLoggingFile
                    Write-Log "Logging settings for '$($site.Name)' exported" "SUCCESS"
                }
                catch {
                    Write-Log "Failed to export logging settings for '$($site.Name)': $_" "WARNING"
                }
            }
        }
    }
    catch {
        Write-Log "Error during FTP messages and logging backup: $_" "ERROR"
    }

    Write-Log "FTP messages and logging backup completed" "SUCCESS"
}

# Backup FTP registry keys
function Backup-FTPRegistry {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP registry keys" "INFO"

    $registryBackupPath = "$BackupFolder\Registry"
    if (-not (Test-Path $registryBackupPath)) {
        New-Item -Path $registryBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export FTPSVC registry keys
        $ftpsvcRegFile = "$registryBackupPath\ftpsvc_registry.reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC" $ftpsvcRegFile /y

        if ($LASTEXITCODE -eq 0) {
            Write-Log "FTPSVC registry keys exported to $ftpsvcRegFile" "SUCCESS"
        }
        else {
            Write-Log "Failed to export FTPSVC registry keys" "ERROR"
        }

        # Export FTP-related IIS registry keys
        $ftpIISRegFile = "$registryBackupPath\ftp_iis_registry.reg"
        reg export "HKLM\SOFTWARE\Microsoft\InetStp" $ftpIISRegFile /y

        if ($LASTEXITCODE -eq 0) {
            Write-Log "FTP IIS registry keys exported to $ftpIISRegFile" "SUCCESS"
        }
        else {
            Write-Log "Failed to export FTP IIS registry keys" "ERROR"
        }
    }
    catch {
        Write-Log "Error during FTP registry backup: $_" "ERROR"
    }

    Write-Log "FTP registry backup completed" "SUCCESS"
}

# Backup FTP content directories
function Backup-FTPContent {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up FTP content directories" "INFO"

    $contentBackupPath = "$BackupFolder\Content"
    if (-not (Test-Path $contentBackupPath)) {
        New-Item -Path $contentBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Get all sites with FTP bindings
        $allSites = Get-Website
        $ftpSitesWithContent = @()

        foreach ($site in $allSites) {
            $ftpBinding = Get-WebBinding -Name $site.Name | Where-Object { $_.protocol -eq "ftp" }

            if ($ftpBinding) {
                $physicalPath = $site.physicalPath

                # Expand environment variables in path (like %SystemDrive%)
                if ($physicalPath) {
                    $physicalPath = [System.Environment]::ExpandEnvironmentVariables($physicalPath)
                }

                if ($physicalPath -and (Test-Path $physicalPath)) {
                    $ftpSitesWithContent += [PSCustomObject]@{
                        SiteName = $site.Name
                        PhysicalPath = $physicalPath
                    }
                }
                else {
                    Write-Log "Physical path not found or inaccessible for FTP site '$($site.Name)': $physicalPath" "WARNING"
                }
            }
        }

        if ($ftpSitesWithContent.Count -eq 0) {
            Write-Log "No FTP sites with accessible content found" "WARNING"
            return
        }

        # Backup content for each FTP site
        foreach ($ftpSite in $ftpSitesWithContent) {
            $siteName = $ftpSite.SiteName
            $sourcePath = $ftpSite.PhysicalPath
            $destPath = "$contentBackupPath\$siteName"

            Write-Log "Backing up content for FTP site '$siteName' from $sourcePath" "INFO"

            try {
                if (-not (Test-Path $destPath)) {
                    New-Item -Path $destPath -ItemType Directory -Force | Out-Null
                }

                # Copy all files and subdirectories
                Copy-Item -Path "$sourcePath\*" -Destination $destPath -Recurse -Force -ErrorAction Continue

                # Get size of backed up content
                $size = (Get-ChildItem -Path $destPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $sizeInMB = [math]::Round($size / 1MB, 2)

                Write-Log "Content for '$siteName' backed up successfully ($sizeInMB MB)" "SUCCESS"
            }
            catch {
                Write-Log "Error backing up content for '$siteName': $_" "ERROR"
            }
        }

        Write-Log "FTP content backup completed for $($ftpSitesWithContent.Count) site(s)" "SUCCESS"
    }
    catch {
        Write-Log "Error during FTP content backup: $_" "ERROR"
    }
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
            BackupType = "FTP Server"
            Creator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            FTPVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
        }

        $metadata | Export-Clixml -Path $metadataFile
        Write-Log "Backup metadata created at $metadataFile" "SUCCESS"

        # Compress the backup if requested
        if ($CreateCompressedArchive) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $archiveName = "$BackupPath\FTP_Backup_$timestamp.zip"

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
function Start-FTPBackup {
    # Start timing
    $startTime = Get-Date

    Write-Log "Starting FTP server backup process" "INFO"
    Write-Log "Backup destination: $BackupPath" "INFO"

    # Create timestamp-based backup folder
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFolder = "$BackupPath\FTP_Backup_$timestamp"

    if (-not (Test-Path $backupFolder)) {
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    }

    # Validate environment
    if (-not (Test-Environment)) {
        Write-Log "Environment validation failed. Aborting backup process." "ERROR"
        return
    }

    # Execute backup steps
    Backup-FTPConfiguration -BackupFolder $backupFolder
    Backup-FTPSites -BackupFolder $backupFolder
    Backup-FTPFirewall -BackupFolder $backupFolder
    Backup-FTPSecurity -BackupFolder $backupFolder
    Backup-FTPSSLCertificates -BackupFolder $backupFolder
    Backup-FTPMessagesAndLogging -BackupFolder $backupFolder
    Backup-FTPRegistry -BackupFolder $backupFolder
    Backup-FTPContent -BackupFolder $backupFolder


    # Create final package
    Create-BackupPackage -BackupFolder $backupFolder -CreateCompressedArchive $Compress

    # Calculate execution time
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).ToString()

    Write-Log "FTP server backup process completed" "SUCCESS"
    Write-Log "Total execution time: $executionTime" "INFO"

    # Return backup location
    return $backupFolder
}

# Start the backup process
$backupLocation = Start-FTPBackup

# Display summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                 FTP SERVER BACKUP COMPLETE                      " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Backup was created at:" -ForegroundColor White
Write-Host $backupLocation -ForegroundColor Green
Write-Host ""
Write-Host "The backup includes:" -ForegroundColor White
Write-Host "- FTP server configuration" -ForegroundColor White
Write-Host "- All FTP sites and bindings" -ForegroundColor White
Write-Host "- FTP content directories (files served by FTP)" -ForegroundColor White
Write-Host "- Authorization rules and authentication settings" -ForegroundColor White
Write-Host "- Firewall settings and passive port configuration" -ForegroundColor White
Write-Host "- User isolation settings" -ForegroundColor White
Write-Host "- FTP messages and logging configuration" -ForegroundColor White
Write-Host "- FTP registry keys" -ForegroundColor White
Write-Host ""
Write-Host "Log file: $LogFile" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
