<#
.SYNOPSIS
    Downloads, installs, and configures Sysmon with the SwiftOnSecurity config.

.DESCRIPTION
    Standalone script that:
    1. Downloads Sysmon from Sysinternals (or uses existing binary)
    2. Downloads SwiftOnSecurity config (or uses local/vendor fallback)
    3. Accepts Sysinternals EULA via registry
    4. Installs Sysmon or updates config if already installed
    5. Verifies service is running and event log has entries

.PARAMETER SysmonConfigPath
    Path to a local Sysmon XML config file. Skips config download if provided.

.PARAMETER InstallDir
    Directory where Sysmon binaries are placed. Default: C:\Sysmon

.EXAMPLE
    .\Install-Sysmon.ps1
    .\Install-Sysmon.ps1 -SysmonConfigPath "C:\configs\sysmon.xml"
    .\Install-Sysmon.ps1 -InstallDir "D:\Tools\Sysmon"
#>

[CmdletBinding()]
param(
    [string]$SysmonConfigPath,
    [string]$InstallDir = "C:\Sysmon"
)

$ErrorActionPreference = "Stop"

# -- Helpers ------------------------------------------------------------------
function Write-Status  { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Success { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Failure { param([string]$Msg) Write-Host "[-] $Msg" -ForegroundColor Red }

# -- 1. Admin check -------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Failure "This script must be run as Administrator."
    exit 1
}
Write-Status "Running as Administrator."

# -- 2. Create install directory -------------------------------------------
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Status "Created install directory: $InstallDir"
} else {
    Write-Status "Install directory exists: $InstallDir"
}

# -- 3. Get Sysmon binary --------------------------------------------------
$sysmonExe = Join-Path $InstallDir "Sysmon64.exe"

if (Test-Path $sysmonExe) {
    Write-Status "Sysmon64.exe already present at $sysmonExe"
} else {
    $zipUrl  = "https://download.sysinternals.com/files/Sysmon.zip"
    $zipPath = Join-Path $InstallDir "Sysmon.zip"

    Write-Status "Downloading Sysmon from $zipUrl ..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Failure "Failed to download Sysmon: $_"
        exit 1
    }

    Write-Status "Extracting Sysmon.zip ..."
    try {
        Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
    } catch {
        Write-Failure "Failed to extract Sysmon.zip: $_"
        exit 1
    }
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $sysmonExe)) {
        Write-Failure "Sysmon64.exe not found after extraction. Check $InstallDir contents."
        exit 1
    }
    Write-Success "Sysmon64.exe extracted to $InstallDir"
}

# -- 4. Get config ---------------------------------------------------------
$configPath = ""
$vendorFallback = Join-Path $PSScriptRoot "..\vendor\sysmon-config\sysmonconfig-export.xml"

if ($SysmonConfigPath) {
    if (-not (Test-Path $SysmonConfigPath)) {
        Write-Failure "Specified config not found: $SysmonConfigPath"
        exit 1
    }
    $configPath = $SysmonConfigPath
    Write-Status "Using provided config: $configPath"
} else {
    # Try downloading SwiftOnSecurity config
    $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $downloadedConfig = Join-Path $InstallDir "sysmonconfig-export.xml"

    Write-Status "Downloading SwiftOnSecurity config ..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $configUrl -OutFile $downloadedConfig -UseBasicParsing
        $configPath = $downloadedConfig
        Write-Success "Config downloaded to $configPath"
    } catch {
        Write-Failure "Download failed: $_"
        # Fallback to vendor copy
        if (Test-Path $vendorFallback) {
            $configPath = $vendorFallback
            Write-Status "Using vendor fallback config: $configPath"
        } else {
            Write-Failure "No config available. Provide one with -SysmonConfigPath or place it at $vendorFallback"
            exit 1
        }
    }
}

# -- 5. Accept Sysinternals EULA -------------------------------------------
Write-Status "Accepting Sysinternals EULA via registry ..."
$eulaKey = "HKCU:\Software\Sysinternals\Sysmon64"
if (-not (Test-Path $eulaKey)) {
    New-Item -Path $eulaKey -Force | Out-Null
}
Set-ItemProperty -Path $eulaKey -Name "EulaAccepted" -Value 1 -Type DWord

# -- 6/7. Install or update ------------------------------------------------
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($svc) {
    Write-Status "Sysmon64 service exists - updating configuration ..."
    $ErrorActionPreference = "Continue"
    & $sysmonExe -c $configPath 2>&1 | ForEach-Object { Write-Host "    $_" }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($sysmonExit -ne 0) {
        Write-Failure "Sysmon config update returned exit code $sysmonExit"
        exit 1
    }
    Write-Success "Sysmon configuration updated."
} else {
    Write-Status "Installing Sysmon64 with config ..."
    $ErrorActionPreference = "Continue"
    & $sysmonExe -accepteula -i $configPath 2>&1 | ForEach-Object { Write-Host "    $_" }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($sysmonExit -ne 0) {
        Write-Failure "Sysmon installation returned exit code $sysmonExit"
        exit 1
    }
    Write-Success "Sysmon installed successfully."
}

# -- 8. Verify -------------------------------------------------------------
Write-Status "Verifying Sysmon service ..."
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    Write-Failure "Sysmon64 service is not running!"
    exit 1
}
Write-Success "Sysmon64 service is running."

Write-Status "Checking for Sysmon event log entries ..."
Start-Sleep -Seconds 2
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction Stop
    Write-Success "Found $($events.Count) recent Sysmon event(s) in the log."
} catch {
    Write-Failure "No Sysmon events found yet (may take a moment): $_"
}

# -- 9. Summary ------------------------------------------------------------
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Sysmon Installation Summary" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Binary:  $sysmonExe"
Write-Host "  Config:  $configPath"
Write-Host "  Service: $($svc.Status)"
Write-Host "  Log:     Microsoft-Windows-Sysmon/Operational"
Write-Host "===================================================" -ForegroundColor Cyan
