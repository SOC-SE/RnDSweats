param (
    # Optional: Specify the IP address of the Splunk Indexer (receiver).
    [string]$INDEXER_IP = "172.20.242.20",

    # Optional: Specify the hostname to be used by Splunk.
    # Defaults to the machine's current hostname.
    [string]$SplunkHostname = $env:COMPUTERNAME,

    # Optional: Specify the admin password for the Splunk forwarder.
    # Required for Splunk 7.1+ silent installs.
    [string]$SplunkPassword = "changeme"
)

# PowerShell script to install and configure Splunk Universal Forwarder on Windows machines
# This was originally written in Bash, then translated to Powershell. An AI was (obviously) used heavily in this process. I only know a small, salty lick of
# PowerShell, this is 70% AI, 25% forums, and 5% me pushing buttons until it worked.
#
# You can be mean to this one. I know it's rough.
#
#  Currently set to v10.0.1. I'm not sure if the link will be valid during the entire competition season
# with how much is still left to go. If the download gives you any trouble, create a Splunk account, go to the universal forwarder downloads, pick the one you want,
# then extract the random set of characters found in the link. In this script, these are stored in the variable "SPLUNK_BUILD".
#
# Samuel Brucker 2024 - 2026

$ErrorActionPreference = "Stop"

# Define variables
$SPLUNK_VERSION = "10.0.2"
$SPLUNK_BUILD = "e2d18b4767e9"
$SPLUNK_MSI_NAME = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-windows-x64.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI_NAME}"
$SPLUNK_MSI_PATH = Join-Path $env:TEMP $SPLUNK_MSI_NAME
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
# $INDEXER_IP is now defined in the param() block at the top
$RECEIVER_PORT = "9997"

# Download Splunk Universal Forwarder MSI
Write-Host "Downloading Splunk Universal Forwarder MSI..."
# Ensure TLS 1.2 is available (older PowerShell defaults to TLS 1.0 which download.splunk.com rejects)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#take away the progress bar, but drastically speeds up downloads on older powershell versions
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri $SPLUNK_DOWNLOAD_URL -OutFile $SPLUNK_MSI_PATH
} catch {
    Write-Host "[ERROR] Failed to download Splunk UF: $_" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $SPLUNK_MSI_PATH)) {
    Write-Host "[ERROR] MSI not found at $SPLUNK_MSI_PATH after download" -ForegroundColor Red
    exit 1
}

# Install Splunk Universal Forwarder
Write-Host "Installing Splunk Universal Forwarder..."
# The $INDEXER_IP variable will be pulled from the parameters
$msiArgs = "/i `"$SPLUNK_MSI_PATH`" AGREETOLICENSE=Yes SPLUNKPASSWORD=$SplunkPassword RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} /quiet"
$install = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($install.ExitCode -ne 0) {
    Write-Host "[ERROR] MSI install failed with exit code $($install.ExitCode)" -ForegroundColor Red
    exit 1
}

# Verify install directory exists
if (-not (Test-Path "$INSTALL_DIR\bin\splunk.exe")) {
    Write-Host "[ERROR] Splunk UF not found at $INSTALL_DIR after install" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Splunk Universal Forwarder installed" -ForegroundColor Green

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."
@"
# -----------------------------------------------------------------------------
# Standard Windows Event Logs
# -----------------------------------------------------------------------------

[WinEventLog://Application]
disabled = 0
index = windows

[WinEventLog://Security]
disabled = 0
index = windows

[WinEventLog://System]
disabled = 0
index = windows

# -----------------------------------------------------------------------------
# Security Services (Defender, Sysmon)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Defender

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Sysmon

# -----------------------------------------------------------------------------
# Lateral Movement Detection (pairs with Zeek AD attack suite)
# Required by Enable-NetworkVisibility.ps1 audit policies
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

[WinEventLog://Microsoft-Windows-WMI-Activity/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:WMI

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:TaskScheduler

# -----------------------------------------------------------------------------
# Security Tools (Suricata, Yara)
# Splunk will gracefully ignore paths that do not exist.
# -----------------------------------------------------------------------------

[monitor://C:\Program Files\Suricata\log\eve.json]
disabled = 0
index = windows
sourcetype = suricata:eve

[monitor://C:\Program Files\Suricata\log\fast.log]
disabled = 0
index = windows
sourcetype = suricata:fast

[monitor://C:\ProgramData\Yara\yara_scans.log]
disabled = 0
index = windows
sourcetype = yara

# -----------------------------------------------------------------------------
# Test Log
# -----------------------------------------------------------------------------

[monitor://C:\tmp\test.log]
disabled = 0
index = windows
sourcetype = test
"@ | Out-File -FilePath $inputsConfPath -Encoding ASCII

# Configure server.conf to use the specified hostname
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"
Write-Host "Setting custom hostname for the logs to '$SplunkHostname'..."
# The $SplunkHostname variable will be pulled from the parameters
@"
[general]
serverName = $SplunkHostname
hostnameOption = shortname
"@ | Out-File -FilePath $serverConfPath -Encoding ASCII

# Restart Splunk Universal Forwarder service to load new inputs.conf
# The MSI installer already starts the service and sets it to auto-start.
# We need a restart to pick up the inputs.conf and server.conf we just wrote.
Write-Host "Restarting Splunk Universal Forwarder service to load configuration..."
Restart-Service SplunkForwarder -Force

# Verify the service is running
Start-Sleep -Seconds 5
$svc = Get-Service SplunkForwarder -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[OK] SplunkForwarder service is running" -ForegroundColor Green
} else {
    Write-Host "[WARN] SplunkForwarder service is not running - check Event Viewer" -ForegroundColor Yellow
}

# Clean up downloaded MSI
Remove-Item $SPLUNK_MSI_PATH -ErrorAction SilentlyContinue

Write-Host "Splunk Universal Forwarder installation and configuration complete!"
