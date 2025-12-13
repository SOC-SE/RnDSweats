#--------------------------------------------------------------
# Script for start of comp
# Made by Logan Schultz
#Version | 1.0
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
# Install Sysmon | So sam can read logs
#--------------------------------------------------------------

# Change to Sysmon config directory
Set-Location "C:\Github\RnDSweats-Development\Windows Branch\COMP\Tools\Sysmon\Configration Files"

# Install Sysmon with config
sysmon -accepteula -i C:\Windows\config.xml

#--------------------------------------------------------------
#Open local Security Policy
#--------------------------------------------------------------

secpol.msc

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
#End of Script
#--------------------------------------------------------------