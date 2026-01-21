#--------------------------------------------------------------
# Script for start of comp
# Made by Logan Schultz
#Version | 1.2
#--------------------------------------------------------------

#--------------------------------------------------------------
# Enumeration
#--------------------------------------------------------------

#Get all Process | Put in txt file
Get-Process > C:\Processoutput.txt

#Get all Admin Accounts | Put in txt file
Get-LocalGroupMember -Group "Administrators"> C:\Adminusers.txt

#--------------------------------------------------------------
# Variables
#--------------------------------------------------------------

# Sysinternals
$urlSY = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$downloadPathSY = "C:\Users\$env:USERNAME\Downloads\SysinternalsSuite.zip"
$extractPathSY = "C:\Sysinternals"

# GitHub
$urlGitHub = "https://codeload.github.com/SOC-SE/RnDSweats/zip/refs/heads/Development"
$downloadPathGitHub = "C:\Users\$env:USERNAME\Downloads\RnDSweats-Development.zip"
$extractPathGitHub = "C:\Github"

#Back Up
$backupfiles = "C:\Backups"

#--------------------------------------------------------------
# Download Files
#--------------------------------------------------------------

# Download Sysinternals
Start-BitsTransfer -Source $urlSY -Destination $downloadPathSY

# Download GitHub Repo
Start-BitsTransfer -Source $urlGitHub -Destination $downloadPathGitHub

#--------------------------------------------------------------
# Create Folders
#--------------------------------------------------------------

# Create extract folder | Sysinternals
if (!(Test-Path $extractPathSY)) {
    New-Item -ItemType Directory -Path $extractPathSY | Out-Null
}

# Create extract folder | GitHub
if (!(Test-Path $extractPathGitHub)) {
    New-Item -ItemType Directory -Path $extractPathGitHub | Out-Null
}

# Create backup Folder
if (!(Test-Path $backupfiles)) {
    New-Item -ItemType Directory -Path $backupfiles | Out-Null
}


#--------------------------------------------------------------
# Unzip Files
#--------------------------------------------------------------

# Extract Sysinternals
Expand-Archive -Path $downloadPathSY -DestinationPath $extractPathSY -Force

# Extract GitHub Repo
Expand-Archive -Path $downloadPathGitHub -DestinationPath $extractPathGitHub -Force

#--------------------------------------------------------------
# Start Sysinternals tools (Run as Admin)
#--------------------------------------------------------------

Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs
Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs
Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs


#--------------------------------------------------------------
#Open local Security Policy
#--------------------------------------------------------------

secpol.msc

#--------------------------------------------------------------
#Open Comper Mangement
#--------------------------------------------------------------

compmgmt.msc

#--------------------------------------------------------------
#Open GPO Mangement
#--------------------------------------------------------------

gpmc.msc

#--------------------------------------------------------------
#Create look backup account | Back Door Bob
#--------------------------------------------------------------

$Password = Read-Host -AsSecureString
$params = @{
    Name        = 'bob'
    Password    = $Password
    FullName    = 'Bob Backdoor'
    Description = 'Nothing to see here blue team'
}

Add-LocalGroupMember -Group "Administrators" -Member "bob"

#--------------------------------------------------------------
#Back ups
#--------------------------------------------------------------

#DNS
$backupPath = "C:\Backups\DNS_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPath -Force
Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force

#Security Policys
$path = "C:\Backups\LocalSecurityPolicy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').inf"
secedit /export /cfg $path

#Registry
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
New-Item -ItemType Directory -Path "C:\Backups\Registry_$ts" -Force

reg export HKLM "C:\Backups\Registry_$ts\HKLM.reg" /y
reg export HKCU "C:\Backups\Registry_$ts\HKCU.reg" /y
reg export HKCR "C:\Backups\Registry_$ts\HKCR.reg" /y
reg export HKU  "C:\Backups\Registry_$ts\HKU.reg"  /y
reg export HKCC "C:\Backups\Registry_$ts\HKCC.reg" /y

#Firewall
$path = "C:\Backups\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#--------------------------------------------------------------
# Install Sysmon | So sam can read logs
#--------------------------------------------------------------

# Change to Sysmon config directory
Set-Location "C:\Github\RnDSweats-Development\Windows Branch\COMP\Tools\Sysmon\Configration Files"

# Install Sysmon with config
sysmon -accepteula -i C:\Github\RnDSweats-Development\Windows Branch\COMP\Tools\Sysmon\Configration Files\config.xml

#--------------------------------------------------------------
#End of Script
#--------------------------------------------------------------