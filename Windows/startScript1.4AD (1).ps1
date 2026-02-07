#--------------------------------------------------------------
# Script for start of comp | AD Server
# Made by Logan Schultz
#Version | 1.4
#--------------------------------------------------------------


#--------------------------------------------------------------
# Timestamp
#--------------------------------------------------------------
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

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

# Disable progress bar to avoid PowerShell 5.1 slowdown bug
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Download Sysinternals
try {
    Invoke-WebRequest -Uri $urlSY -OutFile $downloadPathSY -ErrorAction Stop
    Write-Host "[OK] Sysinternals downloaded" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Sysinternals download failed: $_" -ForegroundColor Yellow
}

# Download GitHub Repo
try {
    Invoke-WebRequest -Uri $urlGitHub -OutFile $downloadPathGitHub -ErrorAction Stop
    Write-Host "[OK] RnDSweats repo downloaded" -ForegroundColor Green
} catch {
    Write-Host "[WARN] RnDSweats download failed - ensure repo is available on USB/local" -ForegroundColor Yellow
}

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
# Create AD account | Bob Backdoor
#--------------------------------------------------------------

Import-Module ActiveDirectory

# Prompt for password
$AccountPassword = Read-Host "Enter password for Bob" -AsSecureString

# Create user (skip if already exists)
$domainDns = (Get-ADDomain).DNSRoot
if (-not (Get-ADUser -Filter 'SamAccountName -eq "bob"' -ErrorAction SilentlyContinue)) {
    New-ADUser `
        -Name "Bob Backdoor" `
        -SamAccountName "bob" `
        -UserPrincipalName "bob@$domainDns" `
        -GivenName "Bob" `
        -Surname "Backdoor" `
        -DisplayName "Bob Backdoor" `
        -Description "Nothing to see here blue team" `
        -AccountPassword $AccountPassword `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ChangePasswordAtLogon $false
}

# Add to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "bob" -ErrorAction SilentlyContinue

# Add to Builtin Administrators
Add-ADGroupMember -Identity "Administrators" -Members "bob" -ErrorAction SilentlyContinue

#--------------------------------------------------------------
#Open Tools
#--------------------------------------------------------------

# Start Sysinternals tools (Run as Admin)
#--------------------------------------------------------------

Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs
Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs
Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs

#Open local Security Policy
#--------------------------------------------------------------

secpol.msc

#Open Computer Mangement
#--------------------------------------------------------------

compmgmt.msc

#Open GPO Mangement
#--------------------------------------------------------------

gpmc.msc

#Open Event Viewer / Logs
#--------------------------------------------------------------

eventvwr.msc

#--------------------------------------------------------------
#Back ups
#--------------------------------------------------------------

#DNS
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\DNS" -Force
$backupPath = "C:\Backups\DNS\DNS_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPath -Force
Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force

#Security Policys
New-Item -ItemType Directory -Path "C:\Backups\LocalSecurity" -Force
$path = "C:\Backups\LocalSecurity\LocalSecurityPolicy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').inf"
secedit /export /cfg $path


#Firewall
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#Audit Policy
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Audit" -Force
#Backup-AuditPolicy -Path C:\Backups\Audit

#GPO
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\GPO" -Force
Backup-GPO -All -Path C:\Backups\GPO

#Registry
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Registry" -Force
New-Item -ItemType Directory -Path "C:\Backups\Registry\Registry_$ts" -Force

reg export HKLM "C:\Backups\Registry\Registry_$ts\HKLM.reg" /y
reg export HKCU "C:\Backups\Registry\Registry_$ts\HKCU.reg" /y
reg export HKCR "C:\Backups\Registry\Registry_$ts\HKCR.reg" /y
reg export HKU  "C:\Backups\Registry\Registry_$ts\HKU.reg"  /y
reg export HKCC "C:\Backups\Registry\Registry_$ts\HKCC.reg" /y

#Web Server Backups
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
$backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force

#--------------------------------------------------------------
# Enumeration
#--------------------------------------------------------------

#Make file paths
New-Item -ItemType Directory -Path "C:\Backups\Enumeration" -Force
New-Item -ItemType Directory -Path "C:\Backups\Enumeration\Process" -Force
New-Item -ItemType Directory -Path "C:\Backups\Enumeration\AdminUsers" -Force

#Get all Process | Put in txt file
Get-Process > C:\Backups\Enumeration\Process\Processoutput_$ts.txt

#Get all Admin Accounts | Put in txt file
Get-LocalGroupMember -Group "Administrators"> C:\Backups\Enumeration\AdminUsers\Adminusers_$ts.txt

#--------------------------------------------------------------
# Install Sysmon | So sam can read logs
#--------------------------------------------------------------

# Change to Sysmon config directory
#Set-Location "C:\Github\RnDSweats-Development\Windows Branch\COMP\Tools\Sysmon\Configration Files"

# Install Sysmon with config
#sysmon -accepteula -i C:\Windows\config.xml

#--------------------------------------------------------------
#Fix vulnerabilities
#--------------------------------------------------------------

#SMB
#--------------------------------------------------------------

#See if SMB is online
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

#Disable SMB1 
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

#Enable SMB2
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force

#Force SMB Client to Refresh Connections
Update-SmbMultichannelConnection

#--------------------------------------------------------------
#End of Script
#--------------------------------------------------------------