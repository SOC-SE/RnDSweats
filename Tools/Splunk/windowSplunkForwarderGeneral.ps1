<#
.SYNOPSIS
    Automates the installation of the Splunk Universal Forwarder on Windows.
    This script downloads the MSI, installs it silently, sets the admin password,
    configures monitors, and sets up forwarding to an indexer.
    
.DESCRIPTION
    This script is a PowerShell conversion of a Linux bash installer.
    It's designed to be run as Administrator.
    It prioritizes speed and efficiency, suitable for competition environments.
    Monitors included:
    - Standard Windows Event Logs (App, Sec, Sys)
    - Windows Defender & Sysmon Event Logs
    - Suricata (eve.json & fast.log) file monitor
    - Yara (scan log) file monitor

.PARAMETER IndexerIp
    The IP address of the Splunk Indexer to forward logs to.
    Default is '172.20.241.20'.

.PARAMETER AdminUsername
    The Splunk admin username. The MSI installer defaults this to 'admin',
    but the script uses this parameter for the 'add forward-server' command.
    Default is 'admin'.

.PARAMETER AdminPassword
    The password for the Splunk admin user. This will be set during installation.
    Default is 'Changeme1!'.

.EXAMPLE
    .\splunkForwarderWindowsGeneral.ps1
    
    Runs the script with all default values.

.EXAMPLE
    .\splunkForwarderWindowsGeneral.ps1 -IndexerIp 10.1.1.5 -AdminPassword "s3cur3p@ss!"
    
    Runs the script, forwarding to 10.1.1.5 and setting a custom admin password.
#>
param(
    [string]$IndexerIp = "172.20.241.20",
    [string]$AdminUsername = "admin",
    [string]$AdminPassword = "Changeme1!"
)

# --- Define Splunk Forwarder Variables ---
$SplunkVersion = "10.0.1"
$SplunkBuild = "8fb2a6c586a5"
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

# Function to install the Splunk Forwarder MSI
function Install-Splunk {
    param(
        [string]$MsiPath,
        [string]$MsiPassword
    )

    Write-Host "Installing Splunk Universal Forwarder..." -ForegroundColor Magenta
    
    # MSI arguments for a silent install
    # We set the admin password and agree to the license.
    # We also log the install, which is good practice.
    $MsiArgs = @(
        "/i", "`"$MsiPath`"",
        "/quiet",
        "/L*v", "`"$env:TEMP\splunk_install.log`"",
        "AGREETOLICENSE=Yes",
        "PASSWORD=""$MsiPassword""",
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

# Function to configure the forwarder to send logs to the Splunk indexer
function Configure-Forwarder {
    param(
        [string]$TargetIndexer,
        [string]$User,
        [string]$Pass
    )
    
    Write-Host "Configuring Splunk Universal Forwarder to send logs to $TargetIndexer:9997..." -ForegroundColor Magenta
    
    # Check if the splunk.exe exists before trying to run it
    if (-not (Test-Path $SplunkBin)) {
        Write-Host "Error: splunk.exe not found at $SplunkBin. Installation may have failed." -ForegroundColor Red
        Exit 1
    }

    $CmdArgs = @(
        "add", "forward-server", "$TargetIndexer:9997",
        "-auth", "$($User):$($Pass)"
    )
    
    $process = Start-Process $SplunkBin -ArgumentList $CmdArgs -Wait -NoNewWindow -PassThru

    if ($process.ExitCode -ne 0) {
        Write-Host "Failed to configure forward-server. Exit code: $($process.ExitCode)" -ForegroundColor Red
    } else {
        Write-Host "Forward-server configuration complete." -ForegroundColor Green
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
Write-Host "Admin Username:  " -ForegroundColor Green -NoNewline
Write-Host $AdminUsername
Write-Host "Admin Password:  " -ForegroundColor Green -NoNewline
Write-Host "(hidden)"
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

# 1. Install Splunk
Install-Splunk -MsiPath $LocalMsiPath -MsiPassword $AdminPassword

# 2. Add monitors
Set-WindowsMonitors

# 3. Configure the forwarder
Configure-Forwarder -TargetIndexer $IndexerIp -User $AdminUsername -Pass $AdminPassword

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