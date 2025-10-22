<#
.SYNOPSIS
    Automates the installation of the Splunk Universal Forwarder on Windows.
    This script downloads the MSI and installs it, pointing it at an indexer.
    
.DESCRIPTION
    This script is a combination of two different install logics.
    It uses the robust checks and monitors from the newer script,
    but the simpler MSI-based configuration from the older script.

.PARAMETER IndexerIp
    The IP address of the Splunk Indexer to forward logs to.
    Default is '172.20.241.20'.

.PARAMETER SplunkHostName
    The custom hostname Splunk will use for this machine.
    Default is the machine's actual $env:COMPUTERNAME.

.EXAMPLE
    .\splunkForwarderWindowsGeneral.ps1
    
    Runs the script with default values.

.EXAMPLE
    .\splunkForwarderWindowsGeneral.ps1 -IndexerIp 10.1.1.5 -SplunkHostName "AD-SERVER-01"
    
    Runs the script, forwarding to 10.1.1.5 and setting a custom hostname.
#>
param(
    [string]$IndexerIp = "172.20.241.20",
    [string]$SplunkHostName = $env:COMPUTERNAME
)

# --- Define Splunk Forwarder Variables ---
# Using the 9.1.1 version from your old script for compatibility with v9.1.0 indexer
$SplunkVersion = "10.0.1"
$SplunkBuild = "c486717c322b"
$SplunkPackageMsi = "splunkforwarder-${SplunkVersion}-${SplunkBuild}-windows-x64.msi"
$SplunkDownloadUrl = "https://download.splunk.com/products/universalforwarder/releases/${SplunkVersion}/windows/${SplunkPackageMsi}"
$InstallDir = "$env:ProgramFiles\SplunkUniversalForwarder"
$SplunkBin = Join-Path $InstallDir "bin\splunk.exe"


# --- Function Definitions ---

# Function to check for Administrator privileges
function Check-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Error: This script must be run as Administrator." -ForegroundColor Red
        Write-Host "Please re-launch in an elevated PowerShell prompt." -ForegroundColor Yellow
        Exit 1
    }
}

# Function to check for basic dependencies (PowerShell 5+ for Invoke-WebRequest)
function Check-Dependencies {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "Error: This script requires PowerShell 5.0 or later." -ForegroundColor Red
        Exit 1
    }
}

# Function to install the Splunk Forwarder MSI (using old script's logic)
function Install-Splunk {
    param(
        [string]$MsiPath,
        [string]$TargetIndexer,
        [string]$TargetPort = "9997"
    )

    Write-Host "Installing Splunk Universal Forwarder..." -ForegroundColor Magenta
    
    # MSI arguments for a silent install
    # Using RECEIVING_INDEXER argument from your old script
    $MsiArgs = @(
        "/i", "`"$MsiPath`"",
        "/quiet",
        "/L*v", "`"$env:TEMP\splunk_install.log`"",
        "AGREETOLICENSE=Yes",
        "RECEIVING_INDEXER=""$TargetIndexer:$TargetPort""",
        "LAUNCH_SPLUNK=1" # Start Splunk service after install
    )

    $process = Start-Process msiexec.exe -ArgumentList $MsiArgs -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Host "Splunk MSI installation failed with exit code: $($process.ExitCode)." -ForegroundColor Red
        Write-Host "Check the log for details: $env:TEMP\splunk_install.log" -ForegroundColor Yellow
        Exit 1
    } else {
        Write-Host "Splunk MSI installation successful." -ForegroundColor Green
    }
}

# Function to set up a consolidated set of monitors
function Set-WindowsMonitors {
    Write-Host "Setting up consolidated monitors..." -ForegroundColor Magenta
    $MonitorConfig = Join-Path $InstallDir "etc\system\local\inputs.conf"

    # Define the monitor stanzas
    $Monitors = @"
# -----------------------------------------------------------------------------
# Standard Windows Event Logs
# -----------------------------------------------------------------------------

[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

# -----------------------------------------------------------------------------
# Security Services (Defender, Sysmon)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Defender

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Sysmon

# -----------------------------------------------------------------------------
# Security Tools (Suricata, Yara)
# Splunk will gracefully ignore paths that do not exist.
# -----------------------------------------------------------------------------

[monitor://C:\Program Files\Suricata\log\eve.json]
disabled = 0
index = main
sourcetype = suricata:eve

[monitor://C:\Program Files\Suricata\log\fast.log]
disabled = 0
index = main
sourcetype = suricata:fast

[monitor://C:\ProgramData\Yara\yara_scans.log]
disabled = 0
index = main
sourcetype = yara

# -----------------------------------------------------------------------------
# Test Log
# -----------------------------------------------------------------------------

[monitor://C:\tmp\test.log]
disabled = 0
index = main
sourcetype = test
"@

    # Write the configuration to inputs.conf
    try {
        $Monitors | Set-Content -Path $MonitorConfig -Encoding UTF8 -ErrorAction Stop
        Write-Host "Monitors configured successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to write $MonitorConfig." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

# Function to set a custom hostname (from old script's logic)
function Set-CustomHostname {
    param(
        [string]$HostName
    )
    Write-Host "Setting custom Splunk hostname to '$HostName'..." -ForegroundColor Magenta
    $ServerConfig = Join-Path $InstallDir "etc\system\local\server.conf"
    
    # This will create the file or append to it if it already exists
    $ConfigContent = @"
[general]
serverName = $HostName
"@
    try {
        $ConfigContent | Out-File -FilePath $ServerConfig -Encoding ASCII -Append -ErrorAction Stop
        Write-Host "Custom hostname set in server.conf." -ForegroundColor Green
    } catch {
        Write-Host "Failed to write $ServerConfig." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

# Function to restart the Splunk service
function Restart-Splunk {
    Write-Host "Restarting Splunk Forwarder service..." -ForegroundColor Magenta
    try {
        Restart-Service SplunkForwarder -ErrorAction Stop
        Write-Host "Splunk Forwarder service successfully restarted." -ForegroundColor Green
    } catch {
        Write-Host "Failed to restart Splunk service." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

# --- SCRIPT EXECUTION STARTS HERE ---
Check-Dependencies
Check-Admin

# Announce the configuration
Write-Host "--- Splunk Forwarder Configuration ---" -ForegroundColor Magenta
Write-Host "Indexer IP:      " -ForegroundColor Green -NoNewline
Write-Host $IndexerIp
Write-Host "Splunk Hostname: " -ForegroundColor Green -NoNewline
Write-Host $SplunkHostName
Write-Host "------------------------------------" -ForegroundColor Magenta

# IDEMPOTENCY CHECK: Exit if Splunk is already installed
if (Test-Path $InstallDir) {
    Write-Host "Splunk Universal Forwarder is already installed in $InstallDir. Aborting installation." -ForegroundColor Yellow
    Exit 0
}

# Set path for the downloaded MSI
$LocalMsiPath = Join-Path $env:TEMP $SplunkPackageMsi


# Download the installer
try {
    Write-Host "Downloading Splunk Forwarder MSI from $SplunkDownloadUrl..." -ForegroundColor Magenta
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $SplunkDownloadUrl -OutFile $LocalMsiPath -ErrorAction Stop
    Write-Host "Download complete." -ForegroundColor Green
} catch {
    Write-Host "Download failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Exit 1
}

# --- Main Installation Logic ---

# 1. Install Splunk (pass in Indexer IP)
Install-Splunk -MsiPath $LocalMsiPath -TargetIndexer $IndexerIp

# 2. Add monitors
Set-WindowsMonitors

# 3. Set custom hostname
Set-CustomHostname -HostName $SplunkHostName

# 4. Restart Splunk to apply settings
Restart-Splunk

# 5. Create test log
Write-Host "Creating test log..." -ForegroundColor Magenta
$TestLogDir = "C:\tmp"
$TestLogFile = Join-Path $TestLogDir "test.log"
if (-not (Test-Path $TestLogDir)) {
    New-Item -Path $TestLogDir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
}
"Test log entry $(Get-Date)" | Set-Content -Path $TestLogFile

# 6. Clean up the installer
Remove-Item $LocalMsiPath -ErrorAction SilentlyContinue

# 7. Verify installation
if (Test-Path $SplunkBin) {
    Write-Host "Verifying installation..." -ForegroundColor Magenta
    & $SplunkBin version
    Write-Host "Splunk Universal Forwarder v$SplunkVersion installation complete!" -ForegroundColor Yellow
} else {
    Write-Host "Installation failed: splunk.exe not found." -ForegroundColor Red
}