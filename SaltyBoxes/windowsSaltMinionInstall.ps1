<#
.SYNOPSIS
    Installs the Salt Minion on Windows using the official Broadcom MSI.

.DESCRIPTION
    Automates Salt Minion installation for Salt-GUI:
    - Verifies Administrator privileges
    - Supports interactive and non-interactive modes
    - Detects OS Architecture (64-bit vs 32-bit)
    - Downloads the correct MSI from the Broadcom repository
    - Performs a quiet install with logging
    - Configures Windows Firewall exceptions
    - Starts the service

.PARAMETER MasterIP
    The IP address or hostname of the Salt Master. Default: 172.20.242.20

.PARAMETER MinionID
    The unique identifier for this minion. Default: system hostname

.PARAMETER SaltVersion
    The Salt version to install. Default: 3007.1

.PARAMETER NonInteractive
    Run without prompts (requires MasterIP parameter)

.EXAMPLE
    # Interactive mode
    .\Install-SaltMinion.ps1

.EXAMPLE
    # Non-interactive mode
    .\Install-SaltMinion.ps1 -MasterIP "172.20.242.20" -MinionID "win-server01" -NonInteractive

.EXAMPLE
    # Specify custom Salt version
    .\Install-SaltMinion.ps1 -MasterIP "10.0.0.1" -SaltVersion "3007.1" -NonInteractive

.NOTES
    Based on original script by Samuel Brucker 2025-2026
    Modified for Salt-GUI integration
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$MasterIP = "",

    [Parameter(Mandatory=$false)]
    [string]$MinionID = "",

    [Parameter(Mandatory=$false)]
    [string]$SaltVersion = "3007.1",

    [Parameter(Mandatory=$false)]
    [switch]$NonInteractive
)

# --- Configuration ---
$DEFAULT_MASTER_IP = "172.20.242.20"
$ErrorActionPreference = "Stop"

# --- Functions ---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $colors = @{
        "INFO" = "Green"
        "WARN" = "Yellow"
        "ERROR" = "Red"
        "DEBUG" = "Cyan"
    }
    $color = $colors[$Level]
    if (-not $color) { $color = "White" }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$Default
    )

    if ($NonInteractive) {
        return $Default
    }

    $response = Read-Host -Prompt "$Prompt [Default: $Default]"
    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }
    return $response
}

function Test-SaltMinionInstalled {
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Stop-ExistingMinion {
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Log "Stopping existing Salt Minion service..." "WARN"
        Stop-Service -Name "salt-minion" -Force
        Start-Sleep -Seconds 2
    }
}

function Get-SaltInstallerUrl {
    param(
        [string]$Version
    )

    if ([Environment]::Is64BitOperatingSystem) {
        Write-Log "Detected 64-bit Operating System"
        $arch = "AMD64"
    } else {
        Write-Log "Detected 32-bit Operating System"
        $arch = "x86"
    }

    $fileName = "Salt-Minion-$Version-Py3-$arch.msi"
    $url = "https://packages.broadcom.com/artifactory/saltproject-generic/windows/$Version/$fileName"

    return @{
        Url = $url
        FileName = $fileName
        Arch = $arch
    }
}

function Install-SaltMinion {
    param(
        [string]$InstallerPath,
        [string]$MasterIP,
        [string]$MinionID,
        [string]$LogPath
    )

    Write-Log "Installing Salt Minion..."
    Write-Log "  Master: $MasterIP"
    Write-Log "  Minion ID: $MinionID"

    $msiArgs = @(
        "/i", "`"$InstallerPath`"",
        "/quiet",
        "/norestart",
        "/log", "`"$LogPath`"",
        "MASTER=$MasterIP",
        "MINION_ID=$MinionID",
        "START_MINION=1"
    )

    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        Write-Log "Installer exited with code: $($process.ExitCode)" "ERROR"
        Write-Log "Check log file: $LogPath" "WARN"
        throw "Installation failed with exit code $($process.ExitCode)"
    }

    Write-Log "Installation completed successfully"
}

function Set-FirewallRules {
    Write-Log "Configuring Windows Firewall..."

    # Common Salt Minion paths
    $saltPaths = @(
        "C:\Program Files\Salt Project\Salt\bin\salt-minion.exe",
        "C:\salt\bin\salt-minion.exe"
    )

    $saltExe = $null
    foreach ($path in $saltPaths) {
        if (Test-Path $path) {
            $saltExe = $path
            break
        }
    }

    if ($saltExe) {
        # Remove existing rules if any
        Get-NetFirewallRule -DisplayName "Salt Minion*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        # Add inbound rule for salt-minion
        New-NetFirewallRule -DisplayName "Salt Minion" `
            -Direction Inbound `
            -Program $saltExe `
            -Action Allow `
            -Profile Any `
            -Description "Allow Salt Minion communication" `
            -ErrorAction SilentlyContinue | Out-Null

        Write-Log "Firewall rules configured for: $saltExe"
    } else {
        Write-Log "Could not find salt-minion.exe - skipping firewall configuration" "WARN"
    }
}

function Start-SaltMinionService {
    Write-Log "Configuring Salt Minion service..."

    $serviceName = "salt-minion"
    $maxAttempts = 5
    $attempt = 0

    # Wait for service to be registered
    while ($attempt -lt $maxAttempts) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            break
        }
        $attempt++
        Write-Log "Waiting for service registration... (attempt $attempt/$maxAttempts)" "DEBUG"
        Start-Sleep -Seconds 2
    }

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Service '$serviceName' not found after installation" "ERROR"
        return $false
    }

    # Set to automatic startup
    Set-Service -Name $serviceName -StartupType Automatic

    # Start if not running
    if ($service.Status -ne 'Running') {
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 3
    }

    # Verify running
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq 'Running') {
        Write-Log "Service '$serviceName' is running"
        return $true
    } else {
        Write-Log "Service '$serviceName' status: $($service.Status)" "WARN"
        return $false
    }
}

# --- Main Script ---

# Banner
Write-Host ""
Write-Host "#####################################################" -ForegroundColor Green
Write-Host "# Salt Minion Installer for Salt-GUI (Windows)      #" -ForegroundColor Green
Write-Host "# Salt Version: $SaltVersion                              #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host ""

# Administrator check
if (-not (Test-Administrator)) {
    Write-Log "This script must be run with Administrator privileges" "ERROR"
    Write-Log "Please right-click and select 'Run as Administrator'" "WARN"
    if (-not $NonInteractive) {
        Read-Host "Press Enter to exit..."
    }
    exit 1
}

# Get Master IP
if ([string]::IsNullOrWhiteSpace($MasterIP)) {
    $MasterIP = Get-UserInput -Prompt "Enter Salt Master IP" -Default $DEFAULT_MASTER_IP
}
Write-Log "Master IP: $MasterIP"

# Get Minion ID
if ([string]::IsNullOrWhiteSpace($MinionID)) {
    $defaultID = $env:COMPUTERNAME
    $MinionID = Get-UserInput -Prompt "Enter Minion ID" -Default $defaultID
}
Write-Log "Minion ID: $MinionID"

# Check for existing installation
if (Test-SaltMinionInstalled) {
    Write-Log "Existing Salt Minion installation detected" "WARN"
    Stop-ExistingMinion
}

# Get installer URL
$installer = Get-SaltInstallerUrl -Version $SaltVersion
$downloadPath = Join-Path $env:TEMP $installer.FileName
$logPath = Join-Path $env:TEMP "salt_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try {
    # Download installer
    Write-Log "Downloading Salt Minion installer..."
    Write-Log "  URL: $($installer.Url)" "DEBUG"
    Write-Log "  Destination: $downloadPath" "DEBUG"

    # Configure TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Download with retry
    $maxRetries = 3
    $retryCount = 0
    $downloaded = $false

    while (-not $downloaded -and $retryCount -lt $maxRetries) {
        try {
            $retryCount++
            Write-Log "Download attempt $retryCount/$maxRetries..."
            Invoke-WebRequest -Uri $installer.Url -OutFile $downloadPath -UseBasicParsing
            $downloaded = $true
        } catch {
            if ($retryCount -lt $maxRetries) {
                Write-Log "Download failed, retrying in 5 seconds..." "WARN"
                Start-Sleep -Seconds 5
            } else {
                throw
            }
        }
    }

    # Verify download
    if (-not (Test-Path $downloadPath)) {
        throw "Installer file not found after download"
    }

    $fileSize = (Get-Item $downloadPath).Length / 1MB
    Write-Log "Downloaded: $([math]::Round($fileSize, 2)) MB"

    # Install
    Install-SaltMinion -InstallerPath $downloadPath -MasterIP $MasterIP -MinionID $MinionID -LogPath $logPath

    # Configure firewall
    Set-FirewallRules

    # Start service
    $serviceStarted = Start-SaltMinionService

    # Summary
    Write-Host ""
    Write-Host "#####################################################" -ForegroundColor Green
    Write-Host "# MINION SETUP COMPLETE                             #" -ForegroundColor Green
    Write-Host "#####################################################" -ForegroundColor Green
    Write-Host ""
    Write-Host "Minion ID:  $MinionID"
    Write-Host "Master IP:  $MasterIP"
    Write-Host "Status:     $(if ($serviceStarted) { 'Running' } else { 'Check Required' })"
    Write-Host "Log File:   $logPath"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Accept the key on the master:"
    Write-Host "     salt-key -a '$MinionID'"
    Write-Host "  2. Test connectivity:"
    Write-Host "     salt '$MinionID' test.ping"
    Write-Host ""

} catch {
    Write-Log "An error occurred: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    if (-not $NonInteractive) {
        Read-Host "Press Enter to exit..."
    }
    exit 1
} finally {
    # Cleanup downloaded installer
    if (Test-Path $downloadPath) {
        Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue
    }
}

if (-not $NonInteractive) {
    Read-Host "Press Enter to exit..."
}
