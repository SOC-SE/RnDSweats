# ==============================================================================
# Script Name : IIS-backup.ps1
# Description : Backs up IIS (Internet Information Services) configuration
#               including websites, application pools, bindings, SSL certificates,
#               and server settings.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.0 - Initial Release
# ==============================================================================
# Usage       : .\IIS-backup.ps1 [backup path] [compress?]
# Notes       :
#   - Must be run with administrative privileges on an IIS server
# ==============================================================================

param(
    [Parameter()]
    [string]$BackupPath = "C:\Backup\IIS",

    [Parameter()]
    [switch]$Compress = $true
)

# Log file setup
$LogDir = "$BackupPath\Logs"
$LogFile = "$LogDir\IISBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

    # Check if IIS service is running
    $iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($iisService.Status -ne "Running") {
        Write-Log "IIS (W3SVC) service is not running" "WARNING"
    }

    Write-Log "Environment validation completed successfully" "SUCCESS"
    return $true
}

# Backup IIS configuration files
function Backup-IISConfiguration {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up IIS configuration files" "INFO"

    $configBackupPath = "$BackupFolder\Configuration"
    if (-not (Test-Path $configBackupPath)) {
        New-Item -Path $configBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Backup applicationHost.config
        $appHostConfig = "$env:windir\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $appHostConfig) {
            Copy-Item -Path $appHostConfig -Destination "$configBackupPath\applicationHost.config" -Force
            Write-Log "applicationHost.config backed up successfully" "SUCCESS"
        }

        # Backup administration.config
        $adminConfig = "$env:windir\System32\inetsrv\config\administration.config"
        if (Test-Path $adminConfig) {
            Copy-Item -Path $adminConfig -Destination "$configBackupPath\administration.config" -Force
            Write-Log "administration.config backed up successfully" "SUCCESS"
        }

        # Backup redirection.config if exists
        $redirectConfig = "$env:windir\System32\inetsrv\config\redirection.config"
        if (Test-Path $redirectConfig) {
            Copy-Item -Path $redirectConfig -Destination "$configBackupPath\redirection.config" -Force
            Write-Log "redirection.config backed up successfully" "SUCCESS"
        }

        # Copy entire config directory structure
        $configDir = "$env:windir\System32\inetsrv\config"
        $configDirBackup = "$configBackupPath\config_full"
        if (Test-Path $configDir) {
            Copy-Item -Path $configDir -Destination $configDirBackup -Recurse -Force
            Write-Log "Full IIS config directory backed up to $configDirBackup" "SUCCESS"
        }
    }
    catch {
        Write-Log "Failed to backup IIS configuration files: $_" "ERROR"
    }

    Write-Log "IIS configuration files backup completed" "SUCCESS"
}

# Backup websites
function Backup-WebSites {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up IIS websites" "INFO"

    $sitesBackupPath = "$BackupFolder\WebSites"
    if (-not (Test-Path $sitesBackupPath)) {
        New-Item -Path $sitesBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Get all websites
        $websites = Get-Website

        # Export all websites list
        $websitesListFile = "$sitesBackupPath\websites_list.xml"
        $websites | Export-Clixml -Path $websitesListFile
        Write-Log "Websites list exported to $websitesListFile" "SUCCESS"

        # Export each website configuration
        foreach ($site in $websites) {
            $siteName = $site.Name
            $siteBackupPath = "$sitesBackupPath\$siteName"

            if (-not (Test-Path $siteBackupPath)) {
                New-Item -Path $siteBackupPath -ItemType Directory -Force | Out-Null
            }

            # Export site configuration
            $siteConfigFile = "$siteBackupPath\site_config.xml"
            $site | Export-Clixml -Path $siteConfigFile
            Write-Log "Website '$siteName' configuration exported" "SUCCESS"

            # Export site bindings
            $bindingsFile = "$siteBackupPath\bindings.xml"
            Get-WebBinding -Name $siteName | Export-Clixml -Path $bindingsFile
            Write-Log "Bindings for '$siteName' exported" "SUCCESS"

            # Export virtual directories
            $vdirsFile = "$siteBackupPath\virtual_directories.xml"
            Get-WebVirtualDirectory -Site $siteName | Export-Clixml -Path $vdirsFile

            # Export web applications
            $appsFile = "$siteBackupPath\applications.xml"
            Get-WebApplication -Site $siteName | Export-Clixml -Path $appsFile
        }
    }
    catch {
        Write-Log "Error during websites backup: $_" "ERROR"
    }

    Write-Log "Websites backup completed" "SUCCESS"
}

# Backup application pools
function Backup-AppPools {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up IIS application pools" "INFO"

    $appPoolsBackupPath = "$BackupFolder\ApplicationPools"
    if (-not (Test-Path $appPoolsBackupPath)) {
        New-Item -Path $appPoolsBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Get all application pools
        $appPools = Get-ChildItem IIS:\AppPools

        # Export all app pools list
        $appPoolsListFile = "$appPoolsBackupPath\apppools_list.xml"
        $appPools | Export-Clixml -Path $appPoolsListFile
        Write-Log "Application pools list exported to $appPoolsListFile" "SUCCESS"

        # Export each app pool configuration
        foreach ($appPool in $appPools) {
            $appPoolName = $appPool.Name
            $appPoolFile = "$appPoolsBackupPath\$appPoolName.xml"
            $appPool | Export-Clixml -Path $appPoolFile
            Write-Log "Application pool '$appPoolName' configuration exported" "SUCCESS"
        }
    }
    catch {
        Write-Log "Error during application pools backup: $_" "ERROR"
    }

    Write-Log "Application pools backup completed" "SUCCESS"
}

# Backup web applications
function Backup-WebApplications {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up web applications" "INFO"

    $appsBackupPath = "$BackupFolder\WebApplications"
    if (-not (Test-Path $appsBackupPath)) {
        New-Item -Path $appsBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Get all web applications
        $webApps = Get-WebApplication

        if ($webApps) {
            $webAppsFile = "$appsBackupPath\web_applications.xml"
            $webApps | Export-Clixml -Path $webAppsFile
            Write-Log "Web applications exported to $webAppsFile" "SUCCESS"
        }
        else {
            Write-Log "No web applications found" "INFO"
        }
    }
    catch {
        Write-Log "Error during web applications backup: $_" "ERROR"
    }

    Write-Log "Web applications backup completed" "SUCCESS"
}

# Backup IIS global settings
function Backup-IISSettings {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up IIS global settings" "INFO"

    $settingsBackupPath = "$BackupFolder\GlobalSettings"
    if (-not (Test-Path $settingsBackupPath)) {
        New-Item -Path $settingsBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export MIME types
        $mimeTypesFile = "$settingsBackupPath\mime_types.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/staticContent" -Name "." | Export-Clixml -Path $mimeTypesFile
        Write-Log "MIME types exported" "SUCCESS"

        # Export handlers
        $handlersFile = "$settingsBackupPath\handlers.xml"
        Get-WebHandler | Export-Clixml -Path $handlersFile
        Write-Log "Handlers exported" "SUCCESS"

        # Export modules
        $modulesFile = "$settingsBackupPath\modules.xml"
        Get-WebGlobalModule | Export-Clixml -Path $modulesFile
        Write-Log "Modules exported" "SUCCESS"

        # Export default documents
        $defaultDocsFile = "$settingsBackupPath\default_documents.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/defaultDocument" -Name "." | Export-Clixml -Path $defaultDocsFile
        Write-Log "Default documents configuration exported" "SUCCESS"

        # Export directory browsing settings
        $dirBrowsingFile = "$settingsBackupPath\directory_browsing.xml"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/directoryBrowse" -Name "." | Export-Clixml -Path $dirBrowsingFile
        Write-Log "Directory browsing settings exported" "SUCCESS"
    }
    catch {
        Write-Log "Error during IIS settings backup: $_" "ERROR"
    }

    Write-Log "IIS settings backup completed" "SUCCESS"
}

# Backup SSL certificates
function Backup-SSLCertificates {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up SSL certificate bindings" "INFO"

    $sslBackupPath = "$BackupFolder\SSL"
    if (-not (Test-Path $sslBackupPath)) {
        New-Item -Path $sslBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export SSL bindings
        $sslBindingsFile = "$sslBackupPath\ssl_bindings.xml"
        Get-ChildItem IIS:\SslBindings | Export-Clixml -Path $sslBindingsFile
        Write-Log "SSL bindings exported to $sslBindingsFile" "SUCCESS"

        # Export certificate information (thumbprints and details)
        $websites = Get-Website
        $certInfo = @()

        foreach ($site in $websites) {
            $bindings = Get-WebBinding -Name $site.Name | Where-Object { $_.protocol -eq "https" }
            foreach ($binding in $bindings) {
                if ($binding.certificateHash) {
                    $certInfo += [PSCustomObject]@{
                        SiteName = $site.Name
                        Binding = $binding.bindingInformation
                        CertificateHash = $binding.certificateHash
                        CertificateStoreName = $binding.certificateStoreName
                    }
                }
            }
        }

        if ($certInfo.Count -gt 0) {
            $certInfoFile = "$sslBackupPath\certificate_info.xml"
            $certInfo | Export-Clixml -Path $certInfoFile
            Write-Log "Certificate information exported" "SUCCESS"
        }

        # Note: Actual certificate private keys are not exported for security reasons
        Write-Log "Note: SSL certificate private keys are not included in backup for security" "INFO"
    }
    catch {
        Write-Log "Error during SSL certificates backup: $_" "ERROR"
    }

    Write-Log "SSL certificates backup completed" "SUCCESS"
}

# Backup IIS registry keys
function Backup-IISRegistry {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up IIS registry keys" "INFO"

    $registryBackupPath = "$BackupFolder\Registry"
    if (-not (Test-Path $registryBackupPath)) {
        New-Item -Path $registryBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Export IIS registry keys
        $iisRegFile = "$registryBackupPath\iis_registry.reg"
        reg export "HKLM\SOFTWARE\Microsoft\InetStp" $iisRegFile /y

        if ($LASTEXITCODE -eq 0) {
            Write-Log "IIS registry keys exported to $iisRegFile" "SUCCESS"
        }
        else {
            Write-Log "Failed to export IIS registry keys" "ERROR"
        }

        # Export W3SVC registry keys
        $w3svcRegFile = "$registryBackupPath\w3svc_registry.reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC" $w3svcRegFile /y

        if ($LASTEXITCODE -eq 0) {
            Write-Log "W3SVC registry keys exported to $w3svcRegFile" "SUCCESS"
        }
        else {
            Write-Log "Failed to export W3SVC registry keys" "ERROR"
        }
    }
    catch {
        Write-Log "Error during IIS registry backup: $_" "ERROR"
    }

    Write-Log "IIS registry backup completed" "SUCCESS"
}

# Backup IIS log files (optional)
function Backup-IISLogs {
    param (
        [string]$BackupFolder
    )

    Write-Log "Backing up IIS log files" "INFO"

    $logsBackupPath = "$BackupFolder\LogFiles"
    if (-not (Test-Path $logsBackupPath)) {
        New-Item -Path $logsBackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Default IIS log location
        $iisLogsPath = "$env:SystemDrive\inetpub\logs\LogFiles"

        if (Test-Path $iisLogsPath) {
            Copy-Item -Path $iisLogsPath -Destination "$logsBackupPath\LogFiles" -Recurse -Force
            Write-Log "IIS log files backed up from $iisLogsPath" "SUCCESS"
        }
        else {
            Write-Log "IIS log files directory not found at $iisLogsPath" "WARNING"
        }
    }
    catch {
        Write-Log "Error during IIS log files backup: $_" "ERROR"
    }

    Write-Log "IIS log files backup completed" "SUCCESS"
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
            BackupType = "IIS Server"
            Creator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            IISVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
        }

        $metadata | Export-Clixml -Path $metadataFile
        Write-Log "Backup metadata created at $metadataFile" "SUCCESS"

        # Compress the backup if requested
        if ($CreateCompressedArchive) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $archiveName = "$BackupPath\IIS_Backup_$timestamp.zip"

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
function Start-IISBackup {
    # Start timing
    $startTime = Get-Date

    Write-Log "Starting IIS server backup process" "INFO"
    Write-Log "Backup destination: $BackupPath" "INFO"

    # Create timestamp-based backup folder
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFolder = "$BackupPath\IIS_Backup_$timestamp"

    if (-not (Test-Path $backupFolder)) {
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    }

    # Validate environment
    if (-not (Test-Environment)) {
        Write-Log "Environment validation failed. Aborting backup process." "ERROR"
        return
    }

    # Execute backup steps
    Backup-IISConfiguration -BackupFolder $backupFolder
    Backup-WebSites -BackupFolder $backupFolder
    Backup-AppPools -BackupFolder $backupFolder
    Backup-WebApplications -BackupFolder $backupFolder
    Backup-IISSettings -BackupFolder $backupFolder
    Backup-SSLCertificates -BackupFolder $backupFolder
    Backup-IISRegistry -BackupFolder $backupFolder

    # Log files backup is optional (can be large)
    # Uncomment the following line if you want to include it
    # Backup-IISLogs -BackupFolder $backupFolder

    # Create final package
    Create-BackupPackage -BackupFolder $backupFolder -CreateCompressedArchive $Compress

    # Calculate execution time
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).ToString()

    Write-Log "IIS server backup process completed" "SUCCESS"
    Write-Log "Total execution time: $executionTime" "INFO"

    # Return backup location
    return $backupFolder
}

# Start the backup process
$backupLocation = Start-IISBackup

# Display summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                 IIS SERVER BACKUP COMPLETE                      " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Backup was created at:" -ForegroundColor White
Write-Host $backupLocation -ForegroundColor Green
Write-Host ""
Write-Host "The backup includes:" -ForegroundColor White
Write-Host "- IIS configuration files (applicationHost.config, etc.)" -ForegroundColor White
Write-Host "- All websites and bindings" -ForegroundColor White
Write-Host "- Application pools" -ForegroundColor White
Write-Host "- Web applications and virtual directories" -ForegroundColor White
Write-Host "- Global IIS settings (MIME types, handlers, modules)" -ForegroundColor White
Write-Host "- SSL certificate bindings and information" -ForegroundColor White
Write-Host "- IIS registry keys" -ForegroundColor White
Write-Host ""
Write-Host "Log file: $LogFile" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
