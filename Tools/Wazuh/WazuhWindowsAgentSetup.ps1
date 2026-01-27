#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Universal Wazuh Agent Installation Script for Windows

.DESCRIPTION
    This script automatically downloads, installs, and configures the Wazuh agent
    on Windows systems, then registers it with a predefined Wazuh manager.

    Manager IP is configurable via parameter or environment variable.

    Created by Samuel Brucker, 2025-2026

.PARAMETER ManagerIP
    The IP address of the Wazuh manager. Defaults to 172.20.242.20

.PARAMETER AgentGroup
    The agent group to assign. Defaults to windows-default

.PARAMETER AgentName
    Custom agent name. Defaults to the computer hostname

.PARAMETER SkipServiceStart
    If specified, installs but doesn't start the service

.EXAMPLE
    .\WazuhWindowsAgentSetup.ps1

.EXAMPLE
    .\WazuhWindowsAgentSetup.ps1 -ManagerIP "192.168.1.100" -AgentGroup "windows-servers"

.EXAMPLE
    .\WazuhWindowsAgentSetup.ps1 -AgentName "DC01-Production"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ManagerIP = $env:WAZUH_MANAGER_IP,

    [Parameter(Mandatory=$false)]
    [string]$AgentGroup = $env:WAZUH_AGENT_GROUP,

    [Parameter(Mandatory=$false)]
    [string]$AgentName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [switch]$SkipServiceStart
)

# ============================================================================
# Configuration
# ============================================================================
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Default values if not provided
if ([string]::IsNullOrEmpty($ManagerIP)) {
    $ManagerIP = "172.20.242.20"
}
if ([string]::IsNullOrEmpty($AgentGroup)) {
    $AgentGroup = "windows-default"
}

# Wazuh version and download URL
$WazuhVersion = "4.9.0-1"
$WazuhMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
$WazuhMsiPath = "$env:TEMP\wazuh-agent.msi"

# Paths
$WazuhInstallDir = "C:\Program Files (x86)\ossec-agent"
$LogFile = "$env:TEMP\wazuh_agent_installer.log"

# ============================================================================
# Utility Functions
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$Level] $timestamp - $Message"

    # Write to console with color
    switch ($Level) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Green }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }

    # Append to log file
    Add-Content -Path $LogFile -Value $logMessage
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-WazuhInstalled {
    return (Test-Path "$WazuhInstallDir\wazuh-agent.exe")
}

function Get-WazuhService {
    return Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
}

# ============================================================================
# Installation Functions
# ============================================================================

function Remove-ExistingWazuh {
    Write-Log "Checking for existing Wazuh installation..."

    $service = Get-WazuhService
    if ($service) {
        Write-Log "Stopping existing Wazuh service..." -Level "WARN"
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    if (Test-WazuhInstalled) {
        Write-Log "Removing existing Wazuh installation..." -Level "WARN"

        # Try to uninstall via MSI
        $uninstallKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Wazuh*" }

        if ($uninstallKey) {
            $uninstallString = $uninstallKey.UninstallString
            if ($uninstallString -match "msiexec") {
                $productCode = $uninstallKey.PSChildName
                Write-Log "Uninstalling Wazuh via MSI (Product: $productCode)..."
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow
                Start-Sleep -Seconds 5
            }
        }

        # Clean up remaining files if any
        if (Test-Path $WazuhInstallDir) {
            Write-Log "Cleaning up remaining files..."
            Remove-Item -Path $WazuhInstallDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Cleanup complete."
}

function Get-WazuhInstaller {
    Write-Log "Downloading Wazuh agent MSI from $WazuhMsiUrl..."

    # Remove existing download if present
    if (Test-Path $WazuhMsiPath) {
        Remove-Item -Path $WazuhMsiPath -Force
    }

    try {
        # Use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Download with progress
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($WazuhMsiUrl, $WazuhMsiPath)

        if (-not (Test-Path $WazuhMsiPath)) {
            throw "Download failed - file not found"
        }

        $fileSize = (Get-Item $WazuhMsiPath).Length / 1MB
        Write-Log "Download complete. File size: $([math]::Round($fileSize, 2)) MB"
    }
    catch {
        Write-Log "Failed to download Wazuh agent: $_" -Level "ERROR"
        throw
    }
}

function Install-WazuhAgent {
    Write-Log "Installing Wazuh agent..."
    Write-Log "  Manager IP: $ManagerIP"
    Write-Log "  Agent Group: $AgentGroup"
    Write-Log "  Agent Name: $AgentName"

    # Build MSI arguments
    $msiArgs = @(
        "/i", $WazuhMsiPath,
        "/qn",
        "/norestart",
        "WAZUH_MANAGER=$ManagerIP",
        "WAZUH_AGENT_GROUP=$AgentGroup",
        "WAZUH_AGENT_NAME=$AgentName",
        "/l*v", "$env:TEMP\wazuh_msi_install.log"
    )

    Write-Log "Running MSI installer..."
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        Write-Log "MSI installation failed with exit code: $($process.ExitCode)" -Level "ERROR"
        Write-Log "Check $env:TEMP\wazuh_msi_install.log for details" -Level "ERROR"
        throw "Installation failed"
    }

    # Verify installation
    Start-Sleep -Seconds 3
    if (-not (Test-WazuhInstalled)) {
        Write-Log "Installation verification failed - agent not found" -Level "ERROR"
        throw "Installation verification failed"
    }

    Write-Log "Wazuh agent installed successfully."
}

function Set-WazuhConfiguration {
    Write-Log "Verifying agent configuration..."

    $configFile = "$WazuhInstallDir\ossec.conf"

    if (-not (Test-Path $configFile)) {
        Write-Log "Configuration file not found at $configFile" -Level "ERROR"
        throw "Configuration file missing"
    }

    # Read and verify manager IP is set
    $configContent = Get-Content $configFile -Raw
    if ($configContent -match "<address>$ManagerIP</address>") {
        Write-Log "Manager IP correctly configured: $ManagerIP"
    }
    else {
        Write-Log "Manager IP may not be correctly set. Updating configuration..." -Level "WARN"

        # Backup original config
        $backupPath = "$configFile.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item -Path $configFile -Destination $backupPath
        Write-Log "Configuration backed up to $backupPath"

        # Update manager address
        $configContent = $configContent -replace '<address>[^<]+</address>', "<address>$ManagerIP</address>"
        Set-Content -Path $configFile -Value $configContent -Encoding UTF8
        Write-Log "Configuration updated with manager IP: $ManagerIP"
    }
}

function Start-WazuhService {
    Write-Log "Starting Wazuh agent service..."

    $service = Get-WazuhService
    if (-not $service) {
        Write-Log "Wazuh service not found. Attempting to register..." -Level "WARN"

        # Try to install the service
        $installService = "$WazuhInstallDir\wazuh-agent.exe"
        if (Test-Path $installService) {
            Start-Process -FilePath $installService -ArgumentList "install-service" -Wait -NoNewWindow
            Start-Sleep -Seconds 2
            $service = Get-WazuhService
        }
    }

    if (-not $service) {
        Write-Log "Failed to find or create Wazuh service" -Level "ERROR"
        throw "Service creation failed"
    }

    # Start the service
    Start-Service -Name "WazuhSvc"
    Start-Sleep -Seconds 5

    # Verify service is running
    $service = Get-WazuhService
    if ($service.Status -eq "Running") {
        Write-Log "Wazuh agent service is running."
    }
    else {
        Write-Log "Service status: $($service.Status)" -Level "WARN"
        Write-Log "Service may need time to connect to manager. Check status later." -Level "WARN"
    }
}

function Show-AgentStatus {
    Write-Log "============================================================"
    Write-Log "Agent Status Information"
    Write-Log "============================================================"

    # Get service status
    $service = Get-WazuhService
    if ($service) {
        Write-Log "Service Status: $($service.Status)"
    }

    # Try to get agent info
    $agentControl = "$WazuhInstallDir\agent-control.exe"
    if (Test-Path $agentControl) {
        try {
            $agentInfo = & $agentControl -i 2>&1
            Write-Log "Agent Info:"
            $agentInfo | ForEach-Object { Write-Log "  $_" }
        }
        catch {
            Write-Log "Could not retrieve agent info" -Level "WARN"
        }
    }
}

function Add-FirewallRules {
    Write-Log "Configuring Windows Firewall rules for Wazuh..."

    # Remove existing rules first
    Get-NetFirewallRule -DisplayName "Wazuh*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    # Add outbound rule for agent communication (port 1514)
    New-NetFirewallRule -DisplayName "Wazuh Agent - Outbound" `
        -Direction Outbound `
        -Protocol TCP `
        -LocalPort Any `
        -RemotePort 1514 `
        -Action Allow `
        -Profile Any `
        -Description "Allow Wazuh agent to communicate with manager" `
        -ErrorAction SilentlyContinue | Out-Null

    # Add outbound rule for enrollment (port 1515)
    New-NetFirewallRule -DisplayName "Wazuh Agent Enrollment - Outbound" `
        -Direction Outbound `
        -Protocol TCP `
        -LocalPort Any `
        -RemotePort 1515 `
        -Action Allow `
        -Profile Any `
        -Description "Allow Wazuh agent enrollment" `
        -ErrorAction SilentlyContinue | Out-Null

    Write-Log "Firewall rules configured."
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    # Initialize log file
    if (Test-Path $LogFile) {
        Remove-Item -Path $LogFile -Force
    }

    Write-Log "============================================================"
    Write-Log "Wazuh Agent Windows Installer"
    Write-Log "============================================================"
    Write-Log "Computer Name: $env:COMPUTERNAME"
    Write-Log "Windows Version: $([Environment]::OSVersion.VersionString)"
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Log "============================================================"

    # Verify administrator privileges
    if (-not (Test-Administrator)) {
        Write-Log "This script must be run as Administrator." -Level "ERROR"
        exit 1
    }

    try {
        # Step 1: Remove existing installation
        Remove-ExistingWazuh

        # Step 2: Download installer
        Get-WazuhInstaller

        # Step 3: Install agent
        Install-WazuhAgent

        # Step 4: Configure agent
        Set-WazuhConfiguration

        # Step 5: Configure firewall
        Add-FirewallRules

        # Step 6: Start service (unless skipped)
        if (-not $SkipServiceStart) {
            Start-WazuhService
        }
        else {
            Write-Log "Service start skipped per user request." -Level "WARN"
        }

        # Step 7: Show status
        Show-AgentStatus

        # Cleanup
        if (Test-Path $WazuhMsiPath) {
            Remove-Item -Path $WazuhMsiPath -Force -ErrorAction SilentlyContinue
        }

        Write-Log "============================================================"
        Write-Log "Wazuh Agent Installation Complete!"
        Write-Log "The agent is configured to report to manager: $ManagerIP"
        Write-Log "Agent Group: $AgentGroup"
        Write-Log "Log file: $LogFile"
        Write-Log "============================================================"
    }
    catch {
        Write-Log "Installation failed: $_" -Level "ERROR"
        Write-Log "Check log file for details: $LogFile" -Level "ERROR"
        exit 1
    }
}

# Run main function
Main
