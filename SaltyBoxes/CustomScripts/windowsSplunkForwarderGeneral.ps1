<#
.SYNOPSIS
    Installs and configures Splunk Universal Forwarder on Windows machines.
    
.DESCRIPTION
    This script automates the installation of the Splunk Universal Forwarder.
    - Downloads the correct MSI from Splunk
    - Configures inputs.conf for comprehensive Windows logging
    - Sets up forwarding to specified indexer
    - Handles common deployment scenarios
    
.PARAMETER INDEXER_IP
    IP address of the Splunk Indexer (default: 172.20.242.20)
    
.PARAMETER SplunkHostname
    Hostname to use in Splunk (default: computer name)
    
.PARAMETER Silent
    Run without prompts

.EXAMPLE
    .\windowsSplunkForwarderGeneral.ps1
    .\windowsSplunkForwarderGeneral.ps1 -INDEXER_IP "10.0.0.5" -Silent
    
.NOTES
    Samuel Brucker 2024-2026
#>

param (
    [string]$INDEXER_IP = "172.20.242.20",
    [string]$SplunkHostname = $env:COMPUTERNAME,
    [switch]$Silent
)

# --- Configuration ---
$SPLUNK_VERSION = "10.0.1"
$SPLUNK_BUILD = "c486717c322b"
$SPLUNK_MSI = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-windows-x64.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI}"
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
$RECEIVER_PORT = "9997"
$MAX_RETRIES = 3

# --- Functions ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DownloadWithRetry {
    param(
        [string]$Url,
        [string]$OutFile,
        [int]$Retries = 3
    )
    
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            Write-Log "Download attempt $i of $Retries..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -ErrorAction Stop
            Write-Log "Download successful" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Download failed: $_" "WARN"
            if ($i -lt $Retries) {
                Start-Sleep -Seconds 5
            }
        }
    }
    return $false
}

# --- Main Script ---
Write-Host @"
=====================================================
  Splunk Universal Forwarder Installer (Windows)
=====================================================
"@ -ForegroundColor Cyan

# Check admin
if (-not (Test-Administrator)) {
    Write-Log "This script requires Administrator privileges" "ERROR"
    Write-Log "Please right-click and select 'Run as Administrator'"
    if (-not $Silent) { Read-Host "Press Enter to exit" }
    exit 1
}

# Check if already installed
if (Test-Path "$INSTALL_DIR\bin\splunk.exe") {
    Write-Log "Splunk Universal Forwarder is already installed at $INSTALL_DIR" "WARN"
    if (-not $Silent) {
        $continue = Read-Host "Continue with reinstall? [y/N]"
        if ($continue -notmatch "^[Yy]") {
            Write-Log "Installation aborted"
            exit 0
        }
    }
    
    # Stop existing service
    Write-Log "Stopping existing Splunk service..."
    Stop-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
}

Write-Log "Configuration:"
Write-Log "  Indexer IP: $INDEXER_IP"
Write-Log "  Hostname: $SplunkHostname"
Write-Log "  Receiver Port: $RECEIVER_PORT"

# Download
$downloadPath = Join-Path $env:TEMP $SPLUNK_MSI
Write-Log "Downloading Splunk Universal Forwarder..."
Write-Log "  URL: $SPLUNK_DOWNLOAD_URL"

if (-not (Get-DownloadWithRetry -Url $SPLUNK_DOWNLOAD_URL -OutFile $downloadPath -Retries $MAX_RETRIES)) {
    Write-Log "All download attempts failed" "ERROR"
    if (-not $Silent) { Read-Host "Press Enter to exit" }
    exit 1
}

# Install
$logPath = Join-Path $env:TEMP "splunk_install.log"
Write-Log "Installing Splunk Universal Forwarder..."

$msiArgs = @(
    "/i", "`"$downloadPath`"",
    "/quiet",
    "/norestart",
    "/log", "`"$logPath`"",
    "AGREETOLICENSE=Yes",
    "RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT}",
    "SPLUNKUSERNAME=admin",
    "GENRANDOMPASSWORD=1",
    "WINEVENTLOG_APP_ENABLE=1",
    "WINEVENTLOG_SEC_ENABLE=1",
    "WINEVENTLOG_SYS_ENABLE=1",
    "WINEVENTLOG_SET_ENABLE=1"
)

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru

if ($process.ExitCode -ne 0) {
    Write-Log "Installation failed with exit code: $($process.ExitCode)" "ERROR"
    Write-Log "Check log file: $logPath"
    if (-not $Silent) { Read-Host "Press Enter to exit" }
    exit 1
}

Write-Log "Installation completed" "SUCCESS"

# Configure inputs.conf
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Log "Configuring inputs.conf..."

$inputsContent = @"
# =============================================================================
# Splunk Universal Forwarder - Windows Inputs Configuration
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# =============================================================================

# -----------------------------------------------------------------------------
# Standard Windows Event Logs
# -----------------------------------------------------------------------------

[WinEventLog://Application]
disabled = 0
index = main
sourcetype = WinEventLog:Application

[WinEventLog://Security]
disabled = 0
index = main
sourcetype = WinEventLog:Security

[WinEventLog://System]
disabled = 0
index = main
sourcetype = WinEventLog:System

[WinEventLog://Setup]
disabled = 0
index = main
sourcetype = WinEventLog:Setup

# -----------------------------------------------------------------------------
# PowerShell Logs (Critical for Security Monitoring)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:PowerShell

[WinEventLog://PowerShellCore/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:PowerShell

# -----------------------------------------------------------------------------
# Windows Defender
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Defender

# -----------------------------------------------------------------------------
# Sysmon (if installed)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Sysmon

# -----------------------------------------------------------------------------
# Task Scheduler (Persistence Detection)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:TaskScheduler

# -----------------------------------------------------------------------------
# Windows Firewall
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Windows Firewall With Advanced Security/Firewall]
disabled = 0
index = main
sourcetype = WinEventLog:Firewall

# -----------------------------------------------------------------------------
# Remote Desktop Services
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:RDP

[WinEventLog://Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:RDP

# -----------------------------------------------------------------------------
# DNS Client (if available)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-DNS-Client/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:DNS

# -----------------------------------------------------------------------------
# Security Tools - Suricata (if installed)
# -----------------------------------------------------------------------------

[monitor://C:\Program Files\Suricata\log\eve.json]
disabled = 0
index = main
sourcetype = suricata:eve

[monitor://C:\Program Files\Suricata\log\fast.log]
disabled = 0
index = main
sourcetype = suricata:fast

# -----------------------------------------------------------------------------
# Security Tools - YARA (if configured)
# -----------------------------------------------------------------------------

[monitor://C:\ProgramData\Yara\yara_scans.log]
disabled = 0
index = main
sourcetype = yara

# -----------------------------------------------------------------------------
# IIS Logs (if installed)
# -----------------------------------------------------------------------------

[monitor://C:\inetpub\logs\LogFiles\*\*.log]
disabled = 0
index = main
sourcetype = iis

# -----------------------------------------------------------------------------
# Test Log
# -----------------------------------------------------------------------------

[monitor://C:\tmp\test.log]
disabled = 0
index = main
sourcetype = test
"@

Set-Content -Path $inputsConfPath -Value $inputsContent -Encoding ASCII
Write-Log "inputs.conf configured"

# Configure server.conf for hostname
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"
$serverContent = @"
[general]
serverName = $SplunkHostname
hostnameOption = shortname
"@

Set-Content -Path $serverConfPath -Value $serverContent -Encoding ASCII
Write-Log "server.conf configured with hostname: $SplunkHostname"

# Configure outputs.conf
$outputsConfPath = "$INSTALL_DIR\etc\system\local\outputs.conf"
$outputsContent = @"
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = ${INDEXER_IP}:${RECEIVER_PORT}

[tcpout-server://${INDEXER_IP}:${RECEIVER_PORT}]
"@

Set-Content -Path $outputsConfPath -Value $outputsContent -Encoding ASCII
Write-Log "outputs.conf configured"

# Configure Firewall
Write-Log "Configuring Windows Firewall..."
$splunkExe = "$INSTALL_DIR\bin\splunk.exe"
$splunkdExe = "$INSTALL_DIR\bin\splunkd.exe"

try {
    # Remove existing rules
    Get-NetFirewallRule -DisplayName "Splunk*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    
    # Add new rules
    New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Inbound -Program $splunkExe -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "Splunk Daemon" -Direction Inbound -Program $splunkdExe -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "Splunk Management" -Direction Inbound -Protocol TCP -LocalPort 8089 -Action Allow -Profile Any | Out-Null
    
    Write-Log "Firewall rules configured" "SUCCESS"
}
catch {
    Write-Log "Failed to configure firewall: $_" "WARN"
}

# Start Service
Write-Log "Starting Splunk Forwarder service..."

try {
    Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "start" -Wait -NoNewWindow
    Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "enable", "boot-start" -Wait -NoNewWindow
    Write-Log "Service started and configured for boot-start" "SUCCESS"
}
catch {
    Write-Log "Error starting service: $_" "ERROR"
}

# Verify
Start-Sleep -Seconds 5
$service = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue

if ($service -and $service.Status -eq 'Running') {
    Write-Log "Splunk Universal Forwarder is running" "SUCCESS"
} else {
    Write-Log "Service may not be running. Check: Get-Service SplunkForwarder" "WARN"
}

# Create test log
Write-Log "Creating test log..."
$testDir = "C:\tmp"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
}
"Test log entry - $(Get-Date)" | Out-File -FilePath "$testDir\test.log" -Encoding ASCII

# Cleanup
Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue

# Summary
Write-Host @"

=====================================================
  Installation Complete!
=====================================================
  Version:      $SPLUNK_VERSION
  Install Dir:  $INSTALL_DIR
  Indexer:      ${INDEXER_IP}:${RECEIVER_PORT}
  Hostname:     $SplunkHostname
  Service:      $($service.Status)
  
  Verify: Get-Service SplunkForwarder
  Logs:   $INSTALL_DIR\var\log\splunk\splunkd.log
=====================================================
"@ -ForegroundColor Green

if (-not $Silent) {
    Read-Host "Press Enter to exit"
}
