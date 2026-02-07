#--------------------------------------------------------------
# Script for start of comp
# Made by Logan Schultz
# Enhanced with hardening from windowtint.ps1
# Version | 2.0
#--------------------------------------------------------------
param(
    [string]$BackdoorPassword = ""
)

#--------------------------------------------------------------
# Timestamp for backups
#--------------------------------------------------------------
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

#--------------------------------------------------------------
# Enumeration - Enhanced
#--------------------------------------------------------------
function Invoke-Enumeration {
    Write-Host "========================================"
    Write-Host "|        Enumerated Machine Info       |"
    Write-Host "========================================"

    # Create backup directories
    New-Item -ItemType Directory -Path "C:\Backups\Enumeration" -Force | Out-Null
    $enumPath = "C:\Backups\Enumeration\Enumeration_$ts.txt"

    # Domain and hostname info
    $h = Get-WmiObject -Class Win32_ComputerSystem
    $TotalRAM = ([Math]::Round(($h.TotalPhysicalMemory/1GB),0))

    $output = @"
========================================
SYSTEM ENUMERATION - $(Get-Date)
========================================

Domain: $($h.Domain.ToUpper())
Hostname: $($h.Name.ToUpper())
Total RAM: $TotalRAM GB

========================================
CPU Info
========================================
"@
    $output | Out-File $enumPath

    Get-WmiObject -Class Win32_Processor | Select-Object DeviceID, Name, NumberOfCores |
        Format-Table | Out-File $enumPath -Append

    # OS Info
    "`n========================================`nOS Info`n========================================" | Out-File $enumPath -Append
    Get-ComputerInfo -Property "Os*" | Out-File $enumPath -Append

    # Installed Applications
    "`n========================================`nInstalled Applications`n========================================" | Out-File $enumPath -Append
    # Query both 64-bit and 32-bit registry paths on 64-bit systems
    $uninstallPaths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    If((Get-WmiObject Win32_OperatingSystem).OSArchitecture -notlike "*32-bit*") {
        $uninstallPaths += 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    $uninstallPaths | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object {$_.DisplayName -and ($_.DisplayName -notlike "*update for*")} |
        Sort-Object DisplayName -Unique | Select-Object DisplayName, DisplayVersion, Publisher |
        Out-File $enumPath -Append

    # Roles and Features (Server only)
    try {
        "`n========================================`nRoles and Features`n========================================" | Out-File $enumPath -Append
        Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} | Out-File $enumPath -Append
    } catch {
        "Not a Server - skipping roles/features" | Out-File $enumPath -Append
    }

    # Network Shares
    "`n========================================`nNetwork Shares`n========================================" | Out-File $enumPath -Append
    Get-WmiObject -Class Win32_Share | Out-File $enumPath -Append

    # Listening Ports
    "`n========================================`nListening Ports`n========================================" | Out-File $enumPath -Append
    netstat -anb 2>$null | Out-File $enumPath -Append

    # Scheduled Tasks
    "`n========================================`nScheduled Tasks`n========================================" | Out-File $enumPath -Append
    schtasks /query /fo LIST | Out-File $enumPath -Append

    # Local Users and Groups
    "`n========================================`nLocal Users`n========================================" | Out-File $enumPath -Append
    Get-LocalUser | Out-File $enumPath -Append
    "`n========================================`nLocal Groups`n========================================" | Out-File $enumPath -Append
    Get-LocalGroup | Out-File $enumPath -Append
    "`n========================================`nAdministrators Group Members`n========================================" | Out-File $enumPath -Append
    Get-LocalGroupMember -Group "Administrators" | Out-File $enumPath -Append

    # AD Users (if available)
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        "`n========================================`nAD Users`n========================================" | Out-File $enumPath -Append
        Get-ADUser -Filter 'enabled -eq $true' -Properties SamAccountName, DisplayName, MemberOf |
            Select-Object SamAccountName, DisplayName | Out-File $enumPath -Append
    }

    # Running Processes
    "`n========================================`nRunning Processes`n========================================" | Out-File $enumPath -Append
    Get-Process | Select-Object Name, Id, CPU, WorkingSet | Sort-Object CPU -Descending | Out-File $enumPath -Append

    # Services
    "`n========================================`nServices (Running)`n========================================" | Out-File $enumPath -Append
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File $enumPath -Append

    Write-Host "[OK] Enumeration saved to $enumPath" -ForegroundColor Green
}

#--------------------------------------------------------------
# Variables
#--------------------------------------------------------------

# Sysinternals
$urlSY = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$downloadPathSY = "C:\Users\$env:USERNAME\Downloads\SysinternalsSuite.zip"
$extractPathSY = "C:\Sysinternals"

# Sysmon Config
$sysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$sysmonConfigPath = "C:\Sysinternals\sysmonconfig.xml"

# GitHub
$urlGitHub = "https://codeload.github.com/SOC-SE/RnDSweats/zip/refs/heads/Development"
$downloadPathGitHub = "C:\Users\$env:USERNAME\Downloads\RnDSweats-Development.zip"
$extractPathGitHub = "C:\Github"

# Backup
$backupfiles = "C:\Backups"

#--------------------------------------------------------------
# Download Files
#--------------------------------------------------------------
function Invoke-Downloads {
    Write-Host "========================================"
    Write-Host "|          Downloading Tools           |"
    Write-Host "========================================"

    # Create directories
    @($extractPathSY, $extractPathGitHub, $backupfiles) | ForEach-Object {
        if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
    }

    # Download Sysinternals
    Write-Host "Downloading Sysinternals Suite..."
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $urlSY -OutFile $downloadPathSY -ErrorAction Stop
    } catch {
        Write-Host "[WARN] Sysinternals download failed: $_" -ForegroundColor Yellow
    }
    if (Test-Path $downloadPathSY) {
        Expand-Archive -Path $downloadPathSY -DestinationPath $extractPathSY -Force
    }

    # Download Sysmon Config
    Write-Host "Downloading Sysmon configuration..."
    try {
        Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile $sysmonConfigPath -ErrorAction Stop
    } catch {
        Write-Host "[!] Sysmon config download failed, trying vendor fallback..." -ForegroundColor Yellow
        $vendorConfig = Join-Path $PSScriptRoot "..\vendor\sysmon-config\sysmonconfig-export.xml"
        if (Test-Path $vendorConfig) {
            Copy-Item $vendorConfig $sysmonConfigPath
            Write-Host "[OK] Sysmon config loaded from vendor" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Sysmon config not available (no download, no vendor)" -ForegroundColor Red
        }
    }

    # Download GitHub Repo
    Write-Host "Downloading GitHub repository..."
    try {
        Invoke-WebRequest -Uri $urlGitHub -OutFile $downloadPathGitHub -ErrorAction Stop
        if (Test-Path $downloadPathGitHub) {
            Expand-Archive -Path $downloadPathGitHub -DestinationPath $extractPathGitHub -Force
        }
    } catch {
        Write-Host "[WARN] RnDSweats download failed - ensure repo is available on USB/local" -ForegroundColor Yellow
    }

    # Install Sysmon (if not already installed)
    if ((Test-Path "$extractPathSY\Sysmon64.exe") -and (Test-Path $sysmonConfigPath)) {
        $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
        if ($sysmonService) {
            Write-Host "Sysmon already installed, updating config..."
            & "$extractPathSY\Sysmon64.exe" -c $sysmonConfigPath 2>$null
        } else {
            Write-Host "Installing Sysmon..."
            & "$extractPathSY\Sysmon64.exe" -accepteula -i $sysmonConfigPath 2>$null
        }
    }

    Write-Host "[OK] Downloads complete" -ForegroundColor Green
}

#--------------------------------------------------------------
# Open Tools
#--------------------------------------------------------------
function Invoke-OpenTools {
    Write-Host "========================================"
    Write-Host "|          Opening Tools               |"
    Write-Host "========================================"

    # Start Sysinternals tools
    if (Test-Path "$extractPathSY\procexp.exe") {
        Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs
    }
    if (Test-Path "$extractPathSY\tcpview.exe") {
        Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs
    }
    if (Test-Path "$extractPathSY\Autoruns.exe") {
        Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs
    }

    # Open management consoles
    Start-Process "secpol.msc" -ErrorAction SilentlyContinue
    Start-Process "compmgmt.msc" -ErrorAction SilentlyContinue
    Start-Process "eventvwr.msc" -ErrorAction SilentlyContinue
}

#--------------------------------------------------------------
# Create backup account | Back Door Bob
#--------------------------------------------------------------
function Invoke-BackdoorBob {
    Write-Host "========================================"
    Write-Host "|     Creating Backup Account          |"
    Write-Host "========================================"

    # Use parameter if provided, otherwise prompt
    if ($script:BackdoorPassword -ne "") {
        $Password = ConvertTo-SecureString $script:BackdoorPassword -AsPlainText -Force
    } else {
        $Password = Read-Host -AsSecureString -Prompt "Enter password for backup account"
    }

    # Check if user exists
    if (!(Get-LocalUser -Name "bob" -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name "bob" -Password $Password -FullName "Bob Backdoor" -Description "Nothing to see here blue team" -PasswordNeverExpires
    }

    # Add to administrators if not already
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($admins.Name -notcontains "$env:COMPUTERNAME\bob") {
        Add-LocalGroupMember -Group "Administrators" -Member "bob" -ErrorAction SilentlyContinue
    }

    Write-Host "[OK] Backup account configured" -ForegroundColor Green
}

#--------------------------------------------------------------
# Backups
#--------------------------------------------------------------
function Invoke-Backups {
    Write-Host "========================================"
    Write-Host "|          Creating Backups            |"
    Write-Host "========================================"

    # DNS
    if (Test-Path "C:\Windows\System32\dns") {
        New-Item -ItemType Directory -Path "C:\Backups\DNS" -Force | Out-Null
        $backupPath = "C:\Backups\DNS\DNS_$ts"
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Security Policy
    New-Item -ItemType Directory -Path "C:\Backups\LocalSecurity" -Force | Out-Null
    $secPath = "C:\Backups\LocalSecurity\LocalSecurityPolicy_$ts.inf"
    secedit /export /cfg $secPath 2>$null

    # Firewall
    New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force | Out-Null
    $fwPath = "C:\Backups\Firewall\Firewall_$ts.wfw"
    netsh advfirewall export $fwPath 2>$null

    # Audit Policy
    New-Item -ItemType Directory -Path "C:\Backups\Audit" -Force | Out-Null
    auditpol /backup /file:"C:\Backups\Audit\AuditPolicy_$ts.csv" 2>$null

    # Registry
    New-Item -ItemType Directory -Path "C:\Backups\Registry\Registry_$ts" -Force | Out-Null
    reg export HKLM "C:\Backups\Registry\Registry_$ts\HKLM.reg" /y 2>$null
    reg export HKCU "C:\Backups\Registry\Registry_$ts\HKCU.reg" /y 2>$null
    reg export HKCR "C:\Backups\Registry\Registry_$ts\HKCR.reg" /y 2>$null
    reg export HKU  "C:\Backups\Registry\Registry_$ts\HKU.reg"  /y 2>$null
    reg export HKCC "C:\Backups\Registry\Registry_$ts\HKCC.reg" /y 2>$null

    # Web Server (IIS)
    if (Test-Path "C:\inetpub") {
        New-Item -ItemType Directory -Path "C:\Backups\Web" -Force | Out-Null
        $webPath = "C:\Backups\Web\Web_$ts"
        Copy-Item "C:\inetpub\*" $webPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # XAMPP
    if (Test-Path "C:\xampp") {
        New-Item -ItemType Directory -Path "C:\Backups\XAMPP" -Force | Out-Null
        Copy-Item "C:\xampp\htdocs" "C:\Backups\XAMPP\htdocs_$ts" -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item "C:\xampp\mysql" "C:\Backups\XAMPP\mysql_$ts" -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item "C:\xampp\apache\conf" "C:\Backups\XAMPP\apache_conf_$ts" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # SQL Server
    if (Test-Path "C:\Program Files\Microsoft SQL Server") {
        New-Item -ItemType Directory -Path "C:\Backups\SQLServer" -Force | Out-Null
        # Just backup config, not entire installation
        Copy-Item "C:\Program Files\Microsoft SQL Server\*\MSSQL\Binn\*.ini" "C:\Backups\SQLServer\" -Force -ErrorAction SilentlyContinue
    }

    # OpenSSH
    if (Test-Path "C:\ProgramData\ssh") {
        New-Item -ItemType Directory -Path "C:\Backups\OpenSSH" -Force | Out-Null
        Copy-Item "C:\ProgramData\ssh\*" "C:\Backups\OpenSSH\" -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[OK] Backups complete" -ForegroundColor Green
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
    # UAC Hardening
    #----------------------------------------------------------
    Write-Host "Hardening UAC..."
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f 2>$null

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

    Write-Host "[OK] Hardening complete" -ForegroundColor Green
}

#--------------------------------------------------------------
# Main Execution
#--------------------------------------------------------------
Write-Host ""
Write-Host "========================================"
Write-Host "|    Windows Competition Start Script  |"
Write-Host "|            Version 2.0               |"
Write-Host "========================================"
Write-Host ""

# Run all functions
Invoke-Enumeration
Invoke-Downloads
Invoke-Backups
Invoke-BackdoorBob
Invoke-OpenTools
Invoke-Hardening

Write-Host ""
Write-Host "========================================"
Write-Host "|          Script Complete!            |"
Write-Host "========================================"
Write-Host ""
Write-Host "Backups saved to: C:\Backups" -ForegroundColor Cyan
Write-Host "Enumeration saved to: C:\Backups\Enumeration" -ForegroundColor Cyan
Write-Host ""
Write-Host "Consider rebooting to apply all changes." -ForegroundColor Yellow

#--------------------------------------------------------------
# End of Script
#--------------------------------------------------------------
