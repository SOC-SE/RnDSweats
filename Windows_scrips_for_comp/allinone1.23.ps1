#﻿﻿﻿
#--------------------------------------------------------------
# All in one | Script for start of comp
# Made by Logan Schultz
#Version | 1.23
#--------------------------------------------------------------
$ProgressPreference = 'SilentlyContinue'
#--------------------------------------------------------------
# Enumeration
#-------------------------------------------------------------- 
function Start-Enumeration {
    Write-Host "========================================"
    Write-Host "|        System Enumeration            |"
    Write-Host "========================================"
#Make file paths
New-Item -ItemType Directory -Path "C:\Backups\Enumeration" -Force
New-Item -ItemType Directory -Path "C:\Backups\Enumeration\Process" -Force
New-Item -ItemType Directory -Path "C:\Backups\Enumeration\AdminUsers" -Force

#TimeStamp
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

#Get all Process | Put in txt file
#Get-Process > C:\Backups\Enumeration\Process\Processoutput_$ts.txt

# Get all local users and their group memberships, then export to a text file
Get-LocalUser | ForEach-Object {
    $user = $_.Name
    $groups = (Get-LocalGroup | Where-Object {
        (Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue | Where-Object Name -eq $user)
    }).Name -join ", "

    [PSCustomObject]@{
        UserName = $user
        Groups   = if ($groups) { $groups } else { "No Groups" }
    }
} | Out-File -FilePath "C:\Backups\Enumeration\Process\LocalUsersAndGroups_$ts.txt" -Encoding UTF8

    try
    {
        Write-Output "========================================"
        Write-Output "|                                      |"
        Write-Output "|        Enumerated Machine Info       |"
        Write-Output "|                                      |"
        Write-Output "========================================"
    
        $h = Get-WmiObject -Class Win32_ComputerSystem
        $TotalRAM = ([Math]::Round(($h.TotalPhysicalMemory/1GB),0) )
        $mth = @{expression = {$_.DeviceLocator};Label="Slot"},`
                @{expression = {$_.Speed};Label="Speed MHZ"},`
                @{expression = {$_.Manufacturer};Label="Manufacturer"},`
                @{expression = {($_.Capacity/1GB)};Label="Size GB"}
    
        Write-Output "Domain: $( $h.domain.toUpper())"
        Write-Output "HostName: $( $h.name.toUpper())"
        Write-Output "Total RAM: $TotalRAM GB";
            
        Get-CimInstance Win32_PhysicalMemory | ft $mth
    
        Write-Output "CPU Info"
        Write-Output "========================================"
    
    
        $cth = @{expression = {$_.DeviceID};Label="CPUID"},@{expression = {$_.Name};Label="Type"},@{expression = {$_.NumberofCores};Label="Cores"}
        Get-WmiObject -class win32_processor | ft $cth
    
        Write-Output "OS Info"
        Write-Output "========================================"
        Get-ComputerInfo -Property "Os*" 
    
        Write-Output "Installed Apps"
        Write-Output "========================================"
        If((Get-WmiObject Win32_OperatingSystem).OSArchitecture -notlike "*32-bit*") 
        {
            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.Displayname -and ($_.Displayname -notlike "*update for*")  } | sort Displayname | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
        }
        Else 
        {
            Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.Displayname -and ($_.Displayname -notlike "*update for*")  } | sort Displayname | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
        }
    
        try
        {
            Write-Output "Roles and Features"
            Write-Output "========================================"
            Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'}
    
        }
        catch 
        {
            Write-Output "Not a Server"
        }
    
        Write-Output "Shares"
        Write-Output "========================================"
        Get-WmiObject -Class win32_share
    
    
        Write-Output "Listening Processes/Ports"
        Write-Output "========================================"
        netstat.exe -anb | Write-Output 
    
    
        Write-Output "DNS"
        Write-Output "========================================"
        $serveros = Get-ComputerInfo OsName
        if ($serveros -like "*2008 R2*") 
        {
            try 
            {
                    dnscmd /info
            }
            catch 
            {
               Write-Output "Not a DNS server"
            }
        }
        else
        {
            try 
            {
                #Output DNS Settings
                get-dnsserver | out-file 
            }
            catch
            {
                Write-Output "Not a DNS server"
            }
        }
    
        Write-Output "Scheduled Tasks"
        Write-Output "========================================"
        $hostname = hostname
        schtasks /query /s $hostname
    
        Write-Output "Local Users and Groups"
        Write-Output "========================================"
        Get-LocalUser
        Get-LocalGroup
    
        Write-Output "AD Users and Groups"
        Write-Output "========================================"
        if (Get-Module -ListAvailable -Name ActiveDirectory)
        {
            Get-ADUser -Filter 'enabled -eq $true' -Properties SamAccountname,DisplayName,memberof | % {
                New-Object PSObject -Property @{
                UserName = $_.DisplayName
                oSamAccountname= $_.SamAccountname
                Groups = ($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name) -join 
                ","}
                } | Select-Object oSamAccountname,UserName,Groups 
        }
        else 
        {
            Write-Output "AD is not installed"
        }
    
        Write-Host "[OK] " -ForegroundColor Green -NoNewLine
        Write-Host "Enumeration Completed!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[FAILED] " -ForegroundColor Red -NoNewLine
        Write-Host "An error occurred while enumerating, please try again" -ForegroundColor Red 
    }
    
    }

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|      System Enumeration Complete      |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green


#--------------------------------------------------------------
# Github Download
#-------------------------------------------------------------- 
function Download-Github {

    Write-Host "========================================"
    Write-Host "|       Downloading Github             |"
    Write-Host "========================================"

    $urlGitHub = "https://github.com/SOC-SE/RnDSweats/archive/refs/heads/temp.zip"
    $extractPathGitHub = "C:\Github"
    $folderpathdownload ="C:\Users\$env:USERNAME\Downloads\RnDSweats-temp.zip"

    # Create extract folder
    if (!(Test-Path $extractPathGitHub)) {
        New-Item -ItemType Directory -Path $extractPathGitHub | Out-Null
    }

    Write-Host "Starting download of Github..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $urlGitHub -OutFile $folderpathdownload
    Write-Host "Download complete." -ForegroundColor Green

    Expand-Archive -Path $folderpathdownload -DestinationPath $extractPathGitHub -Force 
    Write-Host "Extracting ZIP file..." -ForegroundColor DarkMagenta

    Write-Host "-----------------------------------------" -ForegroundColor Green
    Write-Host "|       Github Setup complete           |" -ForegroundColor Green
    Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Sysinternals
#-------------------------------------------------------------- 
function Download-tools {
    Write-Host "========================================"
    Write-Host "|       Downloading Sysinternals       |"
    Write-Host "========================================"
# Create extract folder | Sysinternals
$extractPathSY = "C:\Sysinternals"
if (!(Test-Path $extractPathSY)) {
    New-Item -ItemType Directory -Path $extractPathSY | Out-Null
}

Write-Host "Starting download of Sysinternals" -ForegroundColor DarkMagenta

# Sysinternals
$urlSY = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$downloadPathSY = "C:\Users\$env:USERNAME\Downloads\SysinternalsSuite.zip"


# Download Sysinternals
Start-BitsTransfer -Source $urlSY -Destination $downloadPathSY 
Write-Host "Extracting ZIP file of Sysinternals" -ForegroundColor DarkMagenta
# Extract Sysinternals
Expand-Archive -Path $downloadPathSY -DestinationPath $extractPathSY -Force

Write-Host "Tool Setup Sysinternals" -ForegroundColor Green

# everthing
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|       Downloading Everthing          |"
    Write-Host "========================================"

# everthing
$url_everthing = "https://www.voidtools.com/Everything-1.4.1.1032.x86-Setup.exe"
$downloadPatheverthing = "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe"
Write-Host "Starting download of Everthing" -ForegroundColor DarkMagenta
# Download Everthing
Start-BitsTransfer -Source $url_everthing -Destination $downloadPatheverthing

Write-Host "Download of Everthing complete" -ForegroundColor Green

# System Informer
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|         System Informer              |"
    Write-Host "========================================"
# Sysinternals
$url_systeminformer = "https://github.com/winsiderss/systeminformer/releases/download/v3.2.25011.2103/systeminformer-3.2.25011-release-setup.exe"
$downloadPathsysteminformer = "C:\Users\$env:USERNAME\Downloads\systeminformer-3.2.25011-release-setup.exe"

Write-Host "Starting Download of System Informer" -ForegroundColor DarkMagenta
# Download Everthing
Start-BitsTransfer -Source $url_systeminformer -Destination $downloadPathsysteminformer
Write-Host "Download of System Informer complete" -ForegroundColor Green
# Root Kit Revealer
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|    Downloading RootKit Revealer      |"
    Write-Host "========================================"
$extractPathrootkitrevealer = "C:\Rootkitzip"
# Create extract folder | Sysmon
if (!(Test-Path $extractPathrootkitrevealer)) {
    New-Item -ItemType Directory -Path $extractPathrootkitrevealer | Out-Null
}
# Sysinternals
$url_rootkitrevealer = "https://download.sysinternals.com/files/RootkitRevealer.zip"
$downloadPath_rootkitrevealer = "C:\Users\$env:USERNAME\Downloads\RootkitRevealer.zip"

Write-Host "Starting Download of RootKit Revealer" -ForegroundColor DarkMagenta
# Download RootKit Revealer
Start-BitsTransfer -Source $url_rootkitrevealer -Destination $downloadPath_rootkitrevealer

Write-Host "Extracting ZIP file of Root Kit Revealer" -ForegroundColor  DarkMagenta
# Extract RootKit Revealer
Expand-Archive -Path $downloadPath_rootkitrevealer -DestinationPath $extractPathrootkitrevealer -Force

Write-Host "Download of RootKit Revealer complete" -ForegroundColor Green

# 7 zip
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|          Downloading 7 zip            |"
    Write-Host "========================================"
#7 zip
$url_7zip = "https://7-zip.org/a/7z2600-x64.exe"
$downloadPath7zip = "C:\Users\$env:USERNAME\Downloads\7z2600-x64.exe"

# Download 7zip
Start-BitsTransfer -Source $url_7zip -Destination $downloadPath7zip

# Malware Bytes
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|     Downloading Malware Bytes        |"
    Write-Host "========================================"

# Malware Bytes
$url_malwarebytes = "https://data-cdn.mbamupdates.com/web/mb5-setup-consumer/MBSetup.exe"
$downloadmalwarebytes = "C:\Users\$env:USERNAME\Downloads\MBSetup.exe"
Write-Host "Starting download of Malware bytes" -ForegroundColor DarkMagenta
# Download Malware Bytes
Start-BitsTransfer -Source $url_malwarebytes -Destination $downloadmalwarebytes

Write-Host "Download of Malwarebytes complete" -ForegroundColor Green

# Sysmon download and install
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|      Downloading Sysmon              |"
    Write-Host "========================================"
$extractPathsysmon = "C:\Sysmonx"
# Create extract folder | Sysmon
if (!(Test-Path $extractPathsysmon)) {
    New-Item -ItemType Directory -Path $extractPathsysmon | Out-Null
}
# Sysmon
#$url_sysmon = "https://download.sysinternals.com/files/Sysmon.zip"
#$downloadPathsysmon = "C:\Users\$env:USERNAME\Downloads\Sysmon.zip"

#sysmon config
#$url_sysconfig = "https://wazuh.com/resources/sysconfig.xml.zip"
#$downloadPathsysmonconfig = "C:\Users\$env:USERNAME\Downloads\sysconfig.xml.zip"
#$extractPathsysconfig = "C:\Sysmonx\Sysmoncon"

# Download Sysmon
#Start-BitsTransfer -Source $url_sysmon -Destination $downloadPathsysmon

#Download Sysmon Config
#Start-BitsTransfer -Source $url_sysconfig -Destination $downloadPathsysmonconfig

# Extract Sysmon
#Expand-Archive -Path $downloadPathsysmon -DestinationPath $downloadPathsysmon -Force

# Extract Sysmon Config
#Expand-Archive -Path $downloadPathsysmonconfig -DestinationPath $extractPathsysconfig -Force

#Move Config to Main Folder
##Move-Item -Path "C:\Sysmonx\Sysmoncon\sysconfig.xml\sysconfig.xml" -Destination "C:\Sysmonx\Sysmon\Sysmon64.exe"
#cd C:\Sysmonx\Sysmon\
#Sysmon64.exe -accepteula -i sysconfig.xml
#cd C:\WINDOWS\system32> 

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           All tools Setup             |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Install Sysmon
#--------------------------------------------------------------
function Install-Sysmon {
param (
    # Optional: Path to a local Sysmon XML config file. Skips config download if provided.
    [string]$ConfigPath,

    # Optional: Directory where Sysmon binaries are placed.
    [string]$InstallDir = "C:\Sysmon"
)

# PowerShell script to install and configure Sysmon with Olaf Hartong's sysmon-modular config.
# Falls back to SwiftOnSecurity if the primary config is unavailable.
# Provide -ConfigPath to skip the download entirely and use your own XML.
#
# Samuel Brucker 2024 - 2026

$ErrorActionPreference = "Stop"

# -- Variables ----------------------------------------------------------------
$SysmonZipUrl    = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonZipPath   = Join-Path $InstallDir "Sysmon.zip"
$SysmonExe       = Join-Path $InstallDir "Sysmon64.exe"
$DefaultConfig   = Join-Path $InstallDir "sysmonconfig.xml"

$PrimaryConfigUrl  = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$FallbackConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

# -- 1. Admin check -----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Running as Administrator." -ForegroundColor Green

# -- 2. Create install directory -----------------------------------------------
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[OK] Created install directory: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "[OK] Install directory exists: $InstallDir" -ForegroundColor Green
}

# -- 3. Download Sysmon --------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

if (Test-Path $SysmonExe) {
    Write-Host "[OK] Sysmon64.exe already present at $SysmonExe" -ForegroundColor Green
} else {
    Write-Host "Downloading Sysmon from $SysmonZipUrl ..."
    try {
        Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZipPath -UseBasicParsing
    } catch {
        Write-Host "[ERROR] Failed to download Sysmon: $_" -ForegroundColor Red
        exit 1
    }

    Write-Host "Extracting Sysmon.zip ..."
    try {
        Expand-Archive -Path $SysmonZipPath -DestinationPath $InstallDir -Force
    } catch {
        Write-Host "[ERROR] Failed to extract Sysmon.zip: $_" -ForegroundColor Red
        exit 1
    }
    Remove-Item $SysmonZipPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $SysmonExe)) {
        Write-Host "[ERROR] Sysmon64.exe not found after extraction. Check $InstallDir contents." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Sysmon64.exe extracted to $InstallDir" -ForegroundColor Green
}

# -- 4. Download config --------------------------------------------------------
$ActiveConfig = ""

if ($ConfigPath) {
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "[ERROR] Specified config not found: $ConfigPath" -ForegroundColor Red
        exit 1
    }
    $ActiveConfig = $ConfigPath
    Write-Host "[OK] Using provided config: $ActiveConfig" -ForegroundColor Green
} else {
    # Primary: Olaf Hartong sysmon-modular
    Write-Host "Downloading Olaf Hartong sysmon-modular config ..."
    try {
        Invoke-WebRequest -Uri $PrimaryConfigUrl -OutFile $DefaultConfig -UseBasicParsing
        $ActiveConfig = $DefaultConfig
        Write-Host "[OK] sysmon-modular config downloaded to $ActiveConfig" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Failed to download sysmon-modular config: $_" -ForegroundColor Yellow
        # Fallback: SwiftOnSecurity
        Write-Host "Downloading SwiftOnSecurity fallback config ..."
        try {
            Invoke-WebRequest -Uri $FallbackConfigUrl -OutFile $DefaultConfig -UseBasicParsing
            $ActiveConfig = $DefaultConfig
            Write-Host "[OK] SwiftOnSecurity config downloaded to $ActiveConfig" -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] Failed to download any config. Provide one with -ConfigPath." -ForegroundColor Red
            exit 1
        }
    }
}

# -- 5. Accept EULA ------------------------------------------------------------
Write-Host "Accepting Sysinternals EULA via registry ..."
$eulaKey = "HKCU:\Software\Sysinternals\Sysmon64"
if (-not (Test-Path $eulaKey)) {
    New-Item -Path $eulaKey -Force | Out-Null
}
Set-ItemProperty -Path $eulaKey -Name "EulaAccepted" -Value 1 -Type DWord
Write-Host "[OK] EULA accepted." -ForegroundColor Green

# -- 6. Install or update ------------------------------------------------------
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($svc) {
    Write-Host "Sysmon64 service exists - updating configuration ..."
    $ErrorActionPreference = "Continue"
    & $SysmonExe -c $ActiveConfig 2>&1 | ForEach-Object { Write-Host "    $_" }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($sysmonExit -ne 0) {
        Write-Host "[ERROR] Sysmon config update returned exit code $sysmonExit" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Sysmon configuration updated." -ForegroundColor Green
} else {
    Write-Host "Installing Sysmon64 ..."
    $ErrorActionPreference = "Continue"
    & $SysmonExe -accepteula -i $ActiveConfig 2>&1 | ForEach-Object { Write-Host "    $_" }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($sysmonExit -ne 0) {
        Write-Host "[ERROR] Sysmon installation returned exit code $sysmonExit" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Sysmon installed successfully." -ForegroundColor Green
}

# -- 7. Verify -----------------------------------------------------------------
Write-Host "Verifying Sysmon service ..."
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    Write-Host "[ERROR] Sysmon64 service is not running!" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Sysmon64 service is running." -ForegroundColor Green

Start-Sleep -Seconds 2
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction Stop
    Write-Host "[OK] Found $($events.Count) recent Sysmon event(s) in the log." -ForegroundColor Green
} catch {
    Write-Host "[WARN] No Sysmon events found yet (may take a moment): $_" -ForegroundColor Yellow
}

# -- 8. Summary ----------------------------------------------------------------
Write-Host ""
Write-Host "=== Sysmon Installation Summary ===" -ForegroundColor Cyan
Write-Host "  Binary:  $SysmonExe"
Write-Host "  Config:  $ActiveConfig"
Write-Host "  Service: $($svc.Status)"
Write-Host "  Log:     Microsoft-Windows-Sysmon/Operational"
Write-Host "===================================" -ForegroundColor Cyan
}

#--------------------------------------------------------------
# Salt Agent
#--------------------------------------------------------------
function agentsetup-salt {
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
    The Salt version to install. Default: 3007.13

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
    .\Install-SaltMinion.ps1 -MasterIP "10.0.0.1" -SaltVersion "3007.13" -NonInteractive

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
    [string]$SaltVersion = "3007.13",

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

    $input = Read-Host -Prompt "$Prompt [Default: $Default]"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    }
    return $input
}

function Test-DomainController {
    $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
    # DomainRole: 4 = Backup DC, 5 = Primary DC
    return ($null -ne $cs) -and ($cs.DomainRole -ge 4)
}

function Test-SaltMinionInstalled {
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Uninstall-ExistingMinion {
    Write-Log "Removing existing Salt Minion to ensure clean install..." "WARN"

    # Stop the service first
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name "salt-minion" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # Find and uninstall via MSI product code
    $product = Get-WmiObject Win32_Product | Where-Object { $_.Name -like '*Salt Minion*' }
    if ($product) {
        Write-Log "Uninstalling: $($product.Name) $($product.Version)"
        $result = $product.Uninstall()
        if ($result.ReturnValue -eq 0) {
            Write-Log "Previous version uninstalled successfully"
        } else {
            Write-Log "Uninstall returned code: $($result.ReturnValue)" "WARN"
        }
        Start-Sleep -Seconds 3
    } else {
        # Fallback: just stop the service if WMI can't find the product
        Write-Log "Could not find MSI product entry, stopping service only" "WARN"
    }
}

function Stop-ExistingMinion {
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Log "Stopping existing Salt Minion service..." "WARN"
        Stop-Service -Name "salt-minion" -Force
        Start-Sleep -Seconds 2
    }
}

function Test-PreFlightChecks {
    param(
        [string]$MasterIP
    )

    Write-Log "Running pre-flight checks..."
    $failed = $false

    # 1. PowerShell Execution Policy - check if GPO blocks script execution
    $machinePolicy = Get-ExecutionPolicy -Scope MachinePolicy
    $userPolicy = Get-ExecutionPolicy -Scope UserPolicy
    if ($machinePolicy -ne 'Undefined' -and $machinePolicy -ne 'Bypass' -and $machinePolicy -ne 'Unrestricted') {
        Write-Log "GPO enforces execution policy: $machinePolicy (MachinePolicy scope)" "ERROR"
        Write-Log "  Fix: Ask domain admin to allow scripts, or run:" "WARN"
        Write-Log "  powershell.exe -ExecutionPolicy Bypass -File $($MyInvocation.ScriptName)" "WARN"
        $failed = $true
    } elseif ($userPolicy -ne 'Undefined' -and $userPolicy -ne 'Bypass' -and $userPolicy -ne 'Unrestricted') {
        Write-Log "GPO enforces execution policy: $userPolicy (UserPolicy scope)" "WARN"
    }

    # 2. PowerShell Language Mode - Constrained Language blocks .NET calls
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        Write-Log "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode" "ERROR"
        Write-Log "  This is typically caused by Device Guard/WDAC policy" "WARN"
        Write-Log "  Salt Minion installation requires FullLanguage mode" "WARN"
        $failed = $true
    }

    # 3. MSI installer restrictions via GPO
    $msiPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue
    if ($msiPolicy) {
        # DisableMSI: 0=never, 1=non-managed only, 2=always
        if ($msiPolicy.DisableMSI -eq 2) {
            Write-Log "GPO blocks all MSI installations (DisableMSI=2)" "ERROR"
            Write-Log "  Fix: Domain admin must set 'Disable Windows Installer' to 'Never'" "WARN"
            $failed = $true
        } elseif ($msiPolicy.DisableMSI -eq 1) {
            Write-Log "GPO restricts non-managed MSI installations" "WARN"
            Write-Log "  Installation may still work for administrators" "WARN"
        }
    }

    # 4. Windows Defender - check if it could quarantine Salt
    $defender = Get-MpPreference -ErrorAction SilentlyContinue
    if ($defender -and -not $defender.DisableRealtimeMonitoring) {
        $saltPath = "C:\Program Files\Salt Project\Salt"
        $excluded = $false
        if ($defender.ExclusionPath) {
            foreach ($exc in $defender.ExclusionPath) {
                if ($saltPath.StartsWith($exc.TrimEnd('\')) -or $exc.TrimEnd('\').StartsWith($saltPath)) {
                    $excluded = $true
                    break
                }
            }
        }
        if (-not $excluded) {
            Write-Log "Windows Defender real-time protection is active" "WARN"
            Write-Log "  Salt may be flagged as a remote admin tool. Adding exclusion..." "WARN"
            try {
                $existing = @()
                if ($defender.ExclusionPath) { $existing = @($defender.ExclusionPath) }
                $newExclusions = $existing + @($saltPath, "C:\ProgramData\Salt Project\Salt") | Select-Object -Unique
                Set-MpPreference -ExclusionPath $newExclusions -ErrorAction Stop
                Write-Log "  Defender exclusions added for Salt directories"
            } catch {
                Write-Log "  Could not add Defender exclusion (may need manual GPO change)" "WARN"
                Write-Log "  If install fails, manually exclude: $saltPath" "WARN"
            }
        }
    }

    # 5. Network proxy detection
    $proxyEnabled = $false
    $winHttpProxy = netsh winhttp show proxy 2>&1 | Out-String
    if ($winHttpProxy -match 'Proxy Server\(s\)\s*:\s*\S') {
        Write-Log "System proxy detected (WinHTTP): check netsh winhttp show proxy" "WARN"
        Write-Log "  Download may fail if proxy requires authentication" "WARN"
        $proxyEnabled = $true
    }
    $ieProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ieProxy -and $ieProxy.ProxyEnable -eq 1) {
        Write-Log "IE/User proxy enabled: $($ieProxy.ProxyServer)" "WARN"
        $proxyEnabled = $true
    }

    # 6. Network connectivity to Salt Master
    $portTest = Test-NetConnection -ComputerName $MasterIP -Port 4506 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if (-not $portTest.TcpTestSucceeded) {
        Write-Log "Cannot reach Salt Master at ${MasterIP}:4506" "ERROR"
        Write-Log "  Check firewall rules and network connectivity" "WARN"
        # Also test 4505
        $pubTest = Test-NetConnection -ComputerName $MasterIP -Port 4505 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if (-not $pubTest.TcpTestSucceeded) {
            Write-Log "  Also cannot reach ${MasterIP}:4505" "ERROR"
        }
        $failed = $true
    } else {
        Write-Log "Salt Master reachable at ${MasterIP}:4506"
    }

    # 7. Firewall GPO override check - local rules may be ignored
    $domainProfile = Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue
    if ($domainProfile -and $domainProfile.Enabled) {
        $gpoRules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.PolicyStoreSource -eq 'GroupPolicy' } |
            Measure-Object
        if ($gpoRules.Count -gt 0) {
            Write-Log "GPO firewall rules detected ($($gpoRules.Count) rules)" "WARN"
            Write-Log "  Local firewall rules may be overridden by domain policy" "WARN"
            Write-Log "  Ensure Salt ports 4505/4506 outbound are allowed in GPO" "WARN"
        }
    }

    # 8. AppLocker check
    try {
        $appLocker = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $msiRules = $appLocker.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Msi' }
        $exeRules = $appLocker.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' }
        if ($msiRules -and $msiRules.Count -gt 0) {
            Write-Log "AppLocker MSI rules are active ($($msiRules.Count) rules)" "WARN"
            Write-Log "  MSI installation may be blocked if not whitelisted" "WARN"
        }
        if ($exeRules -and $exeRules.Count -gt 0) {
            Write-Log "AppLocker EXE rules are active ($($exeRules.Count) rules)" "WARN"
            Write-Log "  salt-minion.exe may be blocked after installation" "WARN"
        }
    } catch {
        # AppLocker not configured - this is fine
    }

    if ($failed) {
        Write-Log "Pre-flight checks found blocking issues (see above)" "ERROR"
        return $false
    }

    Write-Log "Pre-flight checks passed"
    return $true
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

    # Common Salt Minion paths (3007+ installs to root, older to bin/)
    $saltPaths = @(
        "C:\Program Files\Salt Project\Salt\salt-minion.exe",
        "C:\Program Files\Salt Project\Salt\bin\salt-minion.exe",
        "C:\salt\salt-minion.exe",
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

    # On Domain Controllers, use delayed auto-start so salt-minion waits for
    # AD DS (NTDS) to fully initialize after reboot. Without this, Salt's
    # win32net.NetUserGetLocalGroups() call can fail with error 1355 if AD
    # services haven't started yet.
    if ($isDC) {
        Write-Log "Setting delayed auto-start for DC compatibility"
        sc.exe config $serviceName start= delayed-auto | Out-Null
    } else {
        Set-Service -Name $serviceName -StartupType Automatic
    }

    # Start if not running
    if ($service.Status -ne 'Running') {
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 3
    }

    # Check for "Paused" state - a known issue where Salt's SSM service
    # manager fails to fully start (common with VC++ runtime issues or
    # on DCs where AD queries fail during startup)
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq 'Paused') {
        Write-Log "Service entered 'Paused' state, attempting recovery..." "WARN"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 5
        $service = Get-Service -Name $serviceName
    }

    # Verify running
    if ($service.Status -eq 'Running') {
        Write-Log "Service '$serviceName' is running"
        return $true
    } else {
        Write-Log "Service '$serviceName' status: $($service.Status)" "WARN"
        if ($isDC -and $service.Status -ne 'Running') {
            Write-Log "On DCs, the service may need AD to fully start. Try: Restart-Service salt-minion" "WARN"
        }
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

# Detect Domain Controller
$isDC = Test-DomainController
if ($isDC) {
    $dcDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-Log "Domain Controller detected (domain: $dcDomain)" "WARN"
    Write-Log "DC-specific mitigations will be applied" "WARN"
}

# Warn on hostname vs minion ID mismatch
if ($MinionID -ne $env:COMPUTERNAME -and $MinionID -ne $env:COMPUTERNAME.ToLower()) {
    Write-Log "Minion ID '$MinionID' differs from hostname '$($env:COMPUTERNAME)'" "WARN"
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    if ($MinionID -ne $fqdn -and $MinionID -ne $fqdn.ToLower()) {
        Write-Log "Minion ID also differs from FQDN '$fqdn'" "WARN"
    }
}

# Pre-flight checks for common AD/GPO blockers
$preFlightOk = Test-PreFlightChecks -MasterIP $MasterIP
if (-not $preFlightOk) {
    if (-not $NonInteractive) {
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne 'y' -and $continue -ne 'Y') {
            Write-Log "Installation aborted by user"
            exit 1
        }
    } else {
        Write-Log "Pre-flight failures in non-interactive mode, aborting" "ERROR"
        exit 1
    }
}

# Check for existing installation
if (Test-SaltMinionInstalled) {
    Write-Log "Existing Salt Minion installation detected" "WARN"
    Uninstall-ExistingMinion
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
    if ($isDC) {
        Write-Host "DC Mode:    Yes (delayed auto-start enabled)"
    }
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
}

#--------------------------------------------------------------
# Wazuh Agent
#--------------------------------------------------------------
function agentsetup-wazuh {
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
$WazuhVersion = "4.14.2-1"
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
        # Enable TLS 1.2 (and TLS 1.3 if available - not present on Server 2016/2019)
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }

        # Download using Invoke-WebRequest (WebClient is deprecated)
        Write-Log "Downloading (this may take a moment)..."
        Invoke-WebRequest -Uri $WazuhMsiUrl -OutFile $WazuhMsiPath -UseBasicParsing -ErrorAction Stop

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

    # Read and verify manager IP is set using XML parsing
    try {
        [xml]$config = Get-Content $configFile
        $currentAddress = $config.ossec_config.client.server.address
        if ($currentAddress -eq $ManagerIP) {
            Write-Log "Manager IP correctly configured: $ManagerIP"
        }
        else {
            Write-Log "Manager IP is '$currentAddress', updating to '$ManagerIP'..." -Level "WARN"

            # Backup original config
            $backupPath = "$configFile.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item -Path $configFile -Destination $backupPath
            Write-Log "Configuration backed up to $backupPath"

            # Update via XML DOM
            $config.ossec_config.client.server.address = $ManagerIP
            $config.Save($configFile)
            Write-Log "Configuration updated with manager IP: $ManagerIP"
        }
    }
    catch {
        Write-Log "XML parsing failed, falling back to regex replacement..." -Level "WARN"
        $configContent = Get-Content $configFile -Raw
        $backupPath = "$configFile.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item -Path $configFile -Destination $backupPath
        $configContent = $configContent -replace '<address>[^<]+</address>', "<address>$ManagerIP</address>"
        Set-Content -Path $configFile -Value $configContent -Encoding UTF8
        Write-Log "Configuration updated with manager IP: $ManagerIP (regex fallback)"
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
    else {
        Write-Log "agent-control.exe not found at $agentControl" -Level "WARN"
    }
}

function Add-FirewallRules {
    Write-Log "Configuring Windows Firewall rules for Wazuh..."

    # Remove only our specific rules (not all Wazuh* rules)
    Get-NetFirewallRule -DisplayName "Wazuh Agent - Outbound" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName "Wazuh Agent Enrollment - Outbound" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

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
    
}

#--------------------------------------------------------------
# Splunk Agent
#--------------------------------------------------------------
function agentsetup-splunk{
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

# Check for existing installation
if (Test-Path "$INSTALL_DIR\bin\splunk.exe") {
    Write-Host "[OK] Existing Splunk Universal Forwarder found at $INSTALL_DIR - skipping install, updating configuration" -ForegroundColor Cyan
    # Ensure service runs as LocalSystem (needed to read Sysmon, SMBServer, and other protected event logs)
    $svcAccount = (Get-WmiObject Win32_Service -Filter "Name='SplunkForwarder'").StartName
    if ($svcAccount -ne "LocalSystem") {
        Write-Host "Changing SplunkForwarder service account from '$svcAccount' to LocalSystem..."
        sc.exe config SplunkForwarder obj= LocalSystem | Out-Null
    }
} else {
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
    $msiArgs = "/i `"$SPLUNK_MSI_PATH`" AGREETOLICENSE=Yes SPLUNKPASSWORD=$SplunkPassword RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} LOGON_USERNAME=LocalSystem /quiet"
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

    # Clean up downloaded MSI
    Remove-Item $SPLUNK_MSI_PATH -ErrorAction SilentlyContinue
}

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."
@"
## -----------------------------------------------------------------------------
# Testing
# -----------------------------------------------------------------------------

[monitor://C:\temp\test.log]
disabled = 0
index = windows
sourcetype = test

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
# Additional Lateral Movement (WinRM, WMI, SMB, AtExec)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

[WinEventLog://Microsoft-Windows-WinRM/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:WinRM

[WinEventLog://Microsoft-Windows-WMI-Activity/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:WMI

[WinEventLog://Microsoft-Windows-SMBServer/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:SMB

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:TaskScheduler

# -----------------------------------------------------------------------------
# Scored Services
# -----------------------------------------------------------------------------

# This doesn't work :(
[WinEventLog://Microsoft-Windows-DNSServer/Analytical]
disabled = 0
index = windows
renderXml = 1
sourcetype = msdns:analytical

[monitor://C:\Windows\System32\dns\dns*.log]
disabled = 0
index = windows
sourcetype = ms:dns:debug

[monitor://C:\inetpub\logs\LogFiles\W3SVC*\*.log]
disabled = 0
index = windows
sourcetype = ms:iis:auto

[monitor://C:\inetpub\logs\LogFiles\FTPSVC*\*.log]
disabled = 0
index = windows
sourcetype = ms:iis:auto
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

Write-Host "Splunk Universal Forwarder installation and configuration complete!"
}


# Open Sysinternals
#--------------------------------------------------------------
function Open-tools {
    Write-Host "========================================"
    Write-Host "|          Opening Tools               |"
    Write-Host "========================================"
#--------------------------------------------------------------
#Open Tools
#--------------------------------------------------------------

# Start Sysinternals tools (Run as Admin)
#--------------------------------------------------------------
$extractPathSY = "C:\Sysinternals"
Write-Host "Opening procexp" -ForegroundColor Green
Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs

Write-Host "Opening tcpview" -ForegroundColor Green
Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs

Write-Host "Opening Autoruns" -ForegroundColor Green
Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs

#Open local Security Policy
#--------------------------------------------------------------

Write-Host "Opening Local Security Policy" -ForegroundColor Green
secpol.msc

#Open Computer Mangement
#--------------------------------------------------------------

Write-Host "Opening Computer Mangement" -ForegroundColor Green
compmgmt.msc


#Open Event Viewer / Logs
#--------------------------------------------------------------

Write-Host "Opening Event Viewer" -ForegroundColor Green
eventvwr.msc

#Open Everthing
#--------------------------------------------------------------
#$downloadPatheverthing = "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe"
#Write-Host "Opening Everthing" -ForegroundColor Green
#Start-Process "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe" -Verb RunAs
Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           All tools opened            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
#Create look backup account | Back Door Bob
#--------------------------------------------------------------
function Invoke-localbackdoor {
# $password get the password from a user input
$Password = Read-Host -AsSecureString
$params = @{
    Name        = 'bob'
    Password    = $Password
    FullName    = 'Bob Backdoor'
    Description = 'Nothing to see here blue team'
}

Write-Host "Created new user" -ForegroundColor Green
#Creates a local User
New-LocalUser @params -PasswordNeverExpires -ErrorAction SilentlyContinue

Write-Host "Added new user to Administrator's group" -ForegroundColor Green

#Adds the new user to the Administrators group
Add-LocalGroupMember -Group "Administrators" -Member "bob" -ErrorAction SilentlyContinue

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|        Backup Account Created         |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
#Back ups
#-------------------------------------------------------------- 
function Run-Backups {
    Write-Host "========================================"
    Write-Host "|          System Backups              |"
    Write-Host "========================================"
New-Item -ItemType Directory -Path "C:\Backups" -Force

#Timestamp
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Create backup Folder
if (!(Test-Path $backupfiles)) {
    New-Item -ItemType Directory -Path $backupfiles | Out-Null
}
#DNS
#--------------------------------------------------------------

Write-Host "Starting DNS Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\DNS" -Force
$backupPath = "C:\Backups\DNS\DNS_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPath -Force
Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force

Write-Host "DNS Backup complete" -ForegroundColor Green

#Security Policys
#--------------------------------------------------------------
Write-Host "Starting Security Policy's Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\LocalSecurity" -Force
$path = "C:\Backups\LocalSecurity\LocalSecurityPolicy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').inf"
secedit /export /cfg $path

Write-Host "Security Policy's Backup complete" -ForegroundColor Green
    

#Firewall
#--------------------------------------------------------------

Write-Host "Starting Firewall Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

Write-Host "Firewall Backup complete" -ForegroundColor Green

#Audit Policy
#--------------------------------------------------------------

Write-Host "Starting Audit Policy Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Audit" -Force
#Backup-AuditPolicy -Path C:\Backups\Audit

Write-Host "Audit Policy Backup complete" -ForegroundColor Green

#Registry
#--------------------------------------------------------------

Write-Host "Starting Registry Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Registry" -Force
New-Item -ItemType Directory -Path "C:\Backups\Registry\Registry_$ts" -Force

reg export HKLM "C:\Backups\Registry\Registry_$ts\HKLM.reg" /y
reg export HKCU "C:\Backups\Registry\Registry_$ts\HKCU.reg" /y
reg export HKCR "C:\Backups\Registry\Registry_$ts\HKCR.reg" /y
reg export HKU  "C:\Backups\Registry\Registry_$ts\HKU.reg"  /y
reg export HKCC "C:\Backups\Registry\Registry_$ts\HKCC.reg" /y

Write-Host "Registry Backup complete" -ForegroundColor Green

#Web Server Backups
#--------------------------------------------------------------

Write-Host "Starting Web Server Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
$backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force

Write-Host "Web Server Backup complete" -ForegroundColor Green

#FTP Server Backups
#--------------------------------------------------------------

Write-Host "Starting FTP Server Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\FTP" -Force
$backupPathWEB = "C:\Backups\FTP\FTP_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\ftp-site\*" $backupPathWEB -Recurse -Force

#DNS Server Backups
#--------------------------------------------------------------
function run-dnserverbackup{
New-Item -ItemType Directory -Path $BackupDir -Force
        <#
.SYNOPSIS
    Backs up DNS zones and records to JSON.

.DESCRIPTION
    Exports all DNS zones and their resource records
    from a Windows DNS Server using the DnsServer module.
#>

param (
    [string]$DnsServer = "localhost",
    [string]$BackupDir = "C:\Backup\DNS_Server\DNS-Backups"

)

# Ensure backup directory exists
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

$timestamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
$backupFile = Join-Path $BackupDir "DNSBackup_$timestamp.json"

Write-Host "Starting DNS backup from $DnsServer" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "DnsServer module not found. Could not make backup." -ForegroundColor Red
}

Import-Module DnsServer

$backup = @()

$zones = Get-DnsServerZone -ComputerName $DnsServer

foreach ($zone in $zones) {
    Write-Host "Backing up zone: $($zone.ZoneName)" -ForegroundColor Yellow

    $records = Get-DnsServerResourceRecord `
        -ComputerName $DnsServer `
        -ZoneName $zone.ZoneName

    $backup += [PSCustomObject]@{
        ZoneName = $zone.ZoneName
        ZoneType = $zone.ZoneType
        IsDsIntegrated = $zone.IsDsIntegrated
        Records = $records
    }
}

$backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8

Write-Host "DNS backup completed:" -ForegroundColor Green
Write-Host "  $backupFile" -ForegroundColor Gray
    }
# Call DNS Server Backup
#--------------------------------------------------------------
run-dnserverbackup

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           Backup Created              |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Hardening - Enhanced from windowtint.ps1
#-------------------------------------------------------------- 
function Invoke-Hardening {
    Write-Host "========================================"
    Write-Host "|          System Hardening            |"
    Write-Host "========================================"

    #----------------------------------------------------------
    # Windows Updates
    #----------------------------------------------------------
    Write-Host "Configuring Windows Updates..."
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f 2>$null

    #----------------------------------------------------------
    # SMB Hardening
    #----------------------------------------------------------
    Write-Host "Hardening SMB..."
    # Disable SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force

    # Enable SMBv2 with security
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -Type DWORD -Value 1 -Force

    # SMB Security Signatures (require signing)
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f 2>$null

    # Disable admin shares on non-DC machines (breaks GP distribution on DCs)
    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if ($domainRole -lt 4) {
        # Not a DC (0=Standalone WS, 1=Member WS, 2=Standalone Server, 3=Member Server)
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f 2>$null
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f 2>$null
    } else {
        Write-Host "  Skipping admin share disable (Domain Controller detected)" -ForegroundColor Yellow
    }

    # Require SMB encryption (note: Enable-NetworkVisibility.ps1 disables this for Zeek - run that script last if using Zeek)
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RejectUnencryptedAccess /t REG_DWORD /d 1 /f 2>$null

    #----------------------------------------------------------
    # Prevent Zerologon
    #----------------------------------------------------------
    Write-Host "Applying Zerologon protection..."
    Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

    #----------------------------------------------------------
    # TLS 1.2
    #----------------------------------------------------------
    Write-Host "Enabling TLS 1.2..."
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType DWORD -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value 0 -PropertyType DWORD -Force | Out-Null
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    


    #----------------------------------------------------------
    # Windows Defender
    #----------------------------------------------------------
    Write-Host "Configuring Windows Defender..."
    Start-Service WinDefend -ErrorAction SilentlyContinue
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f 2>$null

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue
    } catch {}

    #----------------------------------------------------------
    # Disable dangerous features (if they exist)
    #----------------------------------------------------------
    Write-Host "Disabling dangerous features..."
    @('TFTP', 'TelnetClient', 'TelnetServer', 'SMB1Protocol') | ForEach-Object {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $_ -ErrorAction SilentlyContinue
        if ($feature -and $feature.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart -ErrorAction SilentlyContinue | Out-Null
        }
    }

    #----------------------------------------------------------
    # Disable dangerous services
    #----------------------------------------------------------
    Write-Host "Disabling dangerous services..."
    @('Spooler', 'RemoteRegistry') | ForEach-Object {
        Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
    }

    #----------------------------------------------------------
    # Remove accessibility backdoors
    #----------------------------------------------------------
    Write-Host "Removing accessibility backdoors (IFEO debugger entries)..."
    @('sethc.exe', 'Utilman.exe', 'osk.exe', 'Narrator.exe', 'Magnify.exe') | ForEach-Object {
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_" /v Debugger /f 2>$null
    }

    #----------------------------------------------------------
    # Enable DEP (Data Execution Prevention)
    #----------------------------------------------------------
    Write-Host "Enabling DEP..."
    bcdedit.exe /set "{current}" nx AlwaysOn 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f 2>$null

    #----------------------------------------------------------
    # Disable autorun
    #----------------------------------------------------------
    Write-Host "Disabling autorun..."
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 2>$null

    #----------------------------------------------------------
    # Password policies
    #----------------------------------------------------------
    Write-Host "Enforcing password policies..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f 2>$null

    #----------------------------------------------------------
    # Disable Cortana and web search
    #----------------------------------------------------------
    Write-Host "Disabling Cortana and web search..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 2>$null

    #----------------------------------------------------------
    # Show hidden files and extensions
    #----------------------------------------------------------
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f 2>$null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f 2>$null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f 2>$null

    #----------------------------------------------------------
    # Comprehensive Audit Logging
    #----------------------------------------------------------
    Write-Host "Enabling comprehensive audit logging..."
    auditpol /set /category:* /success:enable /failure:enable 2>$null

    # Key subcategories
    @(
        "Security State Change", "Security System Extension", "System Integrity",
        "Logon", "Logoff", "Account Lockout", "Special Logon",
        "Process Creation", "Process Termination",
        "File System", "Registry", "SAM",
        "User Account Management", "Security Group Management",
        "Audit Policy Change", "Authentication Policy Change",
        "Credential Validation", "Kerberos Authentication Service"
    ) | ForEach-Object {
        auditpol /set /subcategory:"$_" /success:enable /failure:enable 2>$null
    }

    #----------------------------------------------------------
    # PowerShell Logging (Registry-based GPO - cannot be bypassed with -NoProfile)
    #----------------------------------------------------------
    Write-Host "Enabling PowerShell logging via registry GPO..."

    # ScriptBlock logging
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

    # Module logging (log all modules)
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type String -Force

    # Transcription (registry-based, belt-and-suspenders with profile-based below)
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Windows\Logs\PSTranscripts" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    New-Item -ItemType Directory -Path "C:\Windows\Logs\PSTranscripts" -Force | Out-Null

    #----------------------------------------------------------
    # Command-Line in Process Creation Events (Event 4688)
    #----------------------------------------------------------
    Write-Host "Enabling command-line in process creation events..."
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

    #----------------------------------------------------------
    # Credential Protection (WDigest, LSA Protection, Cached Logons)
    #----------------------------------------------------------
    Write-Host "Hardening credential protection..."

    # Disable WDigest (prevents cleartext passwords in memory)
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord -Force

    # Enable LSA Protection (blocks Mimikatz from reading LSASS)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force

    # Reduce cached logons (default is 10, reduce to 2)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "2" -Type String -Force

    #----------------------------------------------------------
    # RDP Hardening
    #----------------------------------------------------------
    Write-Host "Hardening RDP..."

    # Require Network Level Authentication
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force
    # Set security layer to TLS
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type DWord -Force

    # Session timeouts and redirection restrictions
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 1800000 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 900000 -Type DWord -Force
    # Disable drive and clipboard redirection
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Type DWord -Force

    #----------------------------------------------------------
    # Disable LLMNR / NBT-NS / mDNS (anti-Responder)
    #----------------------------------------------------------
    Write-Host "Disabling LLMNR, NBT-NS, and mDNS..."

    # Disable LLMNR
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force

    # Disable NBT-NS on all adapters
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS over TCP/IP
    }

    # Block mDNS via firewall
    New-NetFirewallRule -DisplayName "Block mDNS Inbound (UDP 5353)" -Direction Inbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -Direction Outbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null

    #----------------------------------------------------------
    # Enhanced Windows Defender (ASR Rules)
    #----------------------------------------------------------
    Write-Host "Configuring enhanced Windows Defender with ASR rules..."
    try {
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -PUAProtection 1 -ErrorAction SilentlyContinue

        # Attack Surface Reduction rules (Block mode = 1)
        $asrRules = @(
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",  # Block credential stealing from LSASS
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # Block process creations from PSExec/WMI
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # Block untrusted unsigned processes from USB
            "56a863a9-875e-4185-98a7-b882c64b5ce5",  # Block abuse of exploited vulnerable signed drivers
            "e6db77e5-3df2-4cf1-b95a-636979351e5b",  # Block persistence through WMI event subscription
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block execution of potentially obfuscated scripts
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block Office apps from creating child processes
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"   # Block Adobe Reader from creating child processes
        )
        $asrActions = @(1, 1, 1, 1, 1, 1, 1, 1)  # All in Block mode
        Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRules -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  [WARN] Some Defender features may not be available on this edition" -ForegroundColor Yellow
    }

    #----------------------------------------------------------
    # PowerShell Transcript Logging (Profile-based)
    #----------------------------------------------------------
    Write-Host "Enabling PowerShell transcript logging..."
    $transcriptContent = @'
$path = "C:\Windows\Logs\"
$username = $env:USERNAME
$hostname = hostname
$datetime = Get-Date -f 'MM/dd-HH:mm:ss'
$filename = "transcript-${username}-${hostname}-${datetime}.txt"
$Transcript = Join-Path -Path $path -ChildPath $filename
Start-Transcript -Path $Transcript -Append
'@
    New-Item -Path $profile.AllUsersCurrentHost -Type File -Force -ErrorAction SilentlyContinue | Out-Null
    Set-Content -Path $profile.AllUsersCurrentHost -Value $transcriptContent -Force -ErrorAction SilentlyContinue

    #----------------------------------------------------------
    # Cleanup startup locations
    #----------------------------------------------------------
    Write-Host "Cleaning startup locations..."
    @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*',
        "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
    ) | ForEach-Object {
        $items = Get-ChildItem $_ -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Write-Host "  Removing startup item: $($item.FullName)" -ForegroundColor Yellow
        }
        Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
    }

    # Flush DNS
    ipconfig /flushdns 2>$null | Out-Null


    #----------------------------------------------------------
    #Disable IPV6
    #----------------------------------------------------------
    Write-Host "Disabling IPV6..."
    #Disable IPV6 on NIC
    Disable-NetAdapterBinding -Name "Ethernet" -ComponentID "ms_tcpip6" -Confirm:$false

    
    #----------------------------------------------------------
    # Stop WINRM
    #----------------------------------------------------------

    #Stop the Service
    Stop-Service WinRM
    Set-Service WinRM -StartupType Disabled

    #Remove WinRM Listeners: This ensures the system stops "listening" for management requests on any port.
    #Get-ChildItem -Path WSMan:\localhost\Listener | Remove-Item -Recurse

    #----------------------------------------------------------
    # Stop Print Spooler
    #----------------------------------------------------------
    Stop-Service -Name "Spooler" -Force
    Set-Service -Name "Spooler" -StartupType Disabled

    #----------------------------------------------------------
    # Registry Security startup locations
    #----------------------------------------------------------

    Write-Host "-----------------------------------------" -ForegroundColor Green
    Write-Host "|         Hardening Registry            |" -ForegroundColor Green
    Write-Host "-----------------------------------------" -ForegroundColor Green
    
    #Reg Disable of Print spooler
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 4
    #----------------------------------------------------------
    #Remove Iteam's from Registry
    #----------------------------------------------------------
    #Set-IteamProperty -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad" -Name

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF

    #Remove NJRAT
    #----------------------------------------------------------

    #Reg key one
    if (Test-Path -Path "HKU\S-1-5-21-1605714558-552561641-297346831-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028") {
    Remove-ItemProperty -Path "HKU\S-1-5-21-1605714558-552561641-297346831-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028"
    Write-Host "NJRat Registry key deleted | First key." -ForegroundColor DarkRed
    } else {
    Write-Host "First NJRat Registry key does not exist." -ForegroundColor Green
    }

    #Reg key two
        if (Test-Path -Path "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028") {
    Remove-ItemProperty -Path "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028"
    Write-Host "NJRat Registry key deleted | Second Key." -ForegroundColor DarkRed
    } else {
    Write-Host "sScond NJRat Registry key does not exist." -ForegroundColor Green
    }
        

    #----------------------------------------------------------
    #Disable Windows Server Fatures that have Vulns 
    #----------------------------------------------------------

    # List features
    #----------------------------------------------------------
    Get-WindowsFeature

    #Disable Hyper V
    #---------------------------------------------------------- 
    if ((Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All").State -eq 'Enabled') { 
    Write-Host "Hyper V Enable, Disableing now" -ForegroundColor DarkRed 
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -Confirm:$false
    Write-Host "Hyper V Server Disabled" -ForegroundColor Green
    } else { 
    Write-Host "Hyper V not Enabled" -ForegroundColor Green
    }

    #Disable DHCP Server
    #----------------------------------------------------------
    if ((Get-WindowsOptionalFeature -Online -FeatureName "DHCPServer").State -eq 'Enabled') { 
    Write-Host "DHCP Server Enable, Disableing now"  -ForegroundColor DarkRed 
    Disable-WindowsOptionalFeature -Online -FeatureName "DHCPServer" -NoRestart -Confirm:$false
    Write-Host "DHCP Server Disabled" -ForegroundColor Green
    } else { 
    Write-Host "DHCP Server not Enabled" -ForegroundColor Green
    }

    #Disable Fax Server
    #----------------------------------------------------------
    if ((Get-WindowsOptionalFeature -Online -FeatureName "FaxServer").State -eq 'Enabled') { 
    Write-Host "Fax Server Enable, Disableing now" -ForegroundColor DarkRed
    Disable-WindowsOptionalFeature -Online -FeatureName "FaxServer" -NoRestart -Confirm:$false
    Write-Host "Fax Server Disabled" -ForegroundColor Green
    } else { 
    Write-Host "Fax Server not Enabled" -ForegroundColor Green
    }

    Write-Host "[OK] Hardening complete" -ForegroundColor Green

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|         Hardening complete            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# #Firewall
#------------------------------------------------------------- 
function Invoke-Firewall {
    Write-Host "========================================"
    Write-Host "|        Setting up Firewalls          |"
    Write-Host "========================================"
#--------------------------------------------------------------
# Backup existing firewall config
#--------------------------------------------------------------
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#--------------------------------------------------------------
# Disable NON-Microsoft rules only (safer than nuking everything)
#--------------------------------------------------------------
Get-NetFirewallRule |
Where-Object { $_.Group -notlike "@%SystemRoot%*" } |
Disable-NetFirewallRule

#--------------------------------------------------------------
# AD / DNS CORE
#--------------------------------------------------------------

# DNS
Write-Host "Setting up DNS Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "DNS TCP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS TCP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol UDP -Action Allow

# Kerberos Authentication
Write-Host "Setting up Kerberos Authentication Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Kerberos TCP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos TCP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol UDP -Action Allow

# Kerberos Password Change
Write-Host "Setting up Kerberos Password Change Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Kerberos PW TCP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW TCP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol UDP -Action Allow

# LDAP
Write-Host "Setting up LDAP Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "LDAP TCP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP TCP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol UDP -Action Allow

# LDAPS (if enabled)
Write-Host "Setting up LDAPS Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "LDAPS TCP Inbound 636" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAPS TCP Outbound 636" -Direction Outbound -RemotePort 636 -Protocol TCP -Action Allow

# SMB (SYSVOL / NETLOGON)
Write-Host "Setting up SMB Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "SMB TCP Inbound 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SMB TCP Outbound 445" -Direction Outbound -RemotePort 445 -Protocol TCP -Action Allow

# RPC Endpoint Mapper
Write-Host "Setting up RPC Endpoint Mapper Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "RPC TCP Inbound 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC TCP Outbound 135" -Direction Outbound -RemotePort 135 -Protocol TCP -Action Allow

# RPC Dynamic Range (RESTRICTED)
Write-Host "Setting up RPC Dynamic Range Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 5000-5100 Inbound" -Direction Inbound -LocalPort 5000-5100 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 5000-5100 Outbound" -Direction Outbound -RemotePort 5000-5100 -Protocol TCP -Action Allow

# Time Sync
Write-Host "Setting up Time Sync Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "W32Time UDP Inbound 123" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "W32Time UDP Outbound 123" -Direction Outbound -RemotePort 123 -Protocol UDP -Action Allow

#--------------------------------------------------------------
# NetBIOS (BLOCK)
#--------------------------------------------------------------
Write-Host "Setting up NetBIOS Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 137" -Direction Inbound -LocalPort 137 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 138" -Direction Inbound -LocalPort 138 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block

#--------------------------------------------------------------
# ICMP (Diagnostics)
#--------------------------------------------------------------
Write-Host "Setting up ICMPV4 Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "ICMPv4 Inbound" -Protocol ICMPv4 -Direction Inbound -Action Allow
New-NetFirewallRule -DisplayName "ICMPv4 Outbound" -Protocol ICMPv4 -Direction Outbound -Action Allow

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|          Firewalls created            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}



#-------------------------------------------------------------- 
# #Menu system 
#-------------------------------------------------------------

# Main menu for user interaction
#-------------------------------------------------------------
function Show-Menu {
    Write-Host "========================================"
    Write-Host "|          All In one Script           |"
    Write-Host "========================================"
    Write-Host " "
    Write-Host " "
    Write-Host "`nSelect an option:"
    Write-Host "1. Enumeration"
    Write-Host "2. Download the Github"
    Write-Host "3. Download tools"
    Write-Host "4. Start Backups"
    Write-Host "5. Install Splunk"
    Write-Host "6. Install Salt"
    Write-Host "7. Install Wazuh"
    Write-Host "8. Invoke sysmon"
    Write-Host "9. Firewall"
    Write-Host "10.Create backdoor"
    Write-Host "11.Invoke Harding "
    Write-Host "12.Open Tools"
    Write-Host "13.Exit"
}

# Main script loop
#-------------------------------------------------------------
$choice = ""
while ($choice -ne "13") {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        "1" {
            Start-Enumeration
        }
        "2" {
            Download-Github
        }
        "3" {
            Download-tools
        }
        "4" {
            Run-Backups
        }
        "5" {
            agentsetup-splunk
        }
        "6" {
            agentsetup-salt
        }
        "7" {
            agentsetup-wazuh
        }
        "8" {
            Install-Sysmon
        }
        "9" {
            Invoke-Firewall
        }
        "10" {
            Invoke-localbackdoor
        }
        "11" {
            Invoke-Hardening
        }
        "12" {
            Open-tools
        
        }
        "13" {
            Write-Host "Exiting script..."
        
        default {
            Write-Host "Invalid choice, please try again."
        }
    }
}
}
Read-Host "Press Enter to exit..."

#--------------------------------------------------------------
#End of Script

#--------------------------------------------------------------