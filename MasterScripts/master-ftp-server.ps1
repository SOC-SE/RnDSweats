<#
.SYNOPSIS
    Master hardening script for Windows FTP Server

.DESCRIPTION
    Runs enumeration, hardening, and post-hardening enumeration for
    Windows Server 2022 with FTP services.

.NOTES
    Target: Windows Server 2022 - FTP Server
    Author: CCDC Team
    Date: 2025-2026
    Version: 1.0

    Services Protected: FTP (21), FTP-DATA (20), FTPS (990), RDP (3389)

.EXAMPLE
    .\master-ftp-server.ps1
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "C:\CCDC\Logs"
$LogFile = "$LogDir\master-ftp-server_$Timestamp.log"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $(switch($Level) { "INFO" {"Green"} "WARN" {"Yellow"} "ERROR" {"Red"} default {"White"} })
    Add-Content -Path $LogFile -Value $logMessage
}

function Write-Phase {
    param([string]$Phase)
    Write-Host "`n========== $Phase ==========" -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "`n========== $Phase =========="
}

Write-Host "========================================================"
Write-Host "  WINDOWS FTP SERVER - MASTER HARDENING SCRIPT"
Write-Host "  Target: Windows Server 2022 with FTP"
Write-Host "  Time: $(Get-Date)"
Write-Host "========================================================"

# ============================================================================
# PHASE 1: INITIAL ENUMERATION
# ============================================================================
Write-Phase "PHASE 1: INITIAL ENUMERATION"

$enumDir = "$LogDir\enum_pre_$Timestamp"
New-Item -ItemType Directory -Force -Path $enumDir | Out-Null

systeminfo > "$enumDir\systeminfo.txt"
Get-LocalUser | Format-Table * > "$enumDir\local_users.txt"
Get-Process | Format-Table * > "$enumDir\processes.txt"
Get-Service | Format-Table * > "$enumDir\services.txt"
netstat -ano > "$enumDir\netstat.txt"

# FTP-specific enumeration
if (Get-Command Get-WebConfiguration -ErrorAction SilentlyContinue) {
    Get-WebConfiguration -Filter /system.ftpServer -PSPath IIS:\ > "$enumDir\ftp_config.txt" -ErrorAction SilentlyContinue
}

Write-Log "Pre-enumeration saved to $enumDir"

# ============================================================================
# PHASE 2: QUICK HARDENING
# ============================================================================
Write-Phase "PHASE 2: QUICK HARDENING"

$quickHarden = "$RepoDir\SaltyBoxes\CustomScripts\quickHarden.ps1"
if (Test-Path $quickHarden) {
    Write-Log "Running quickHarden.ps1..."
    & $quickHarden 2>&1 | Tee-Object -FilePath $LogFile -Append
} else {
    Write-Log "Applying manual hardening..."

    $servicesToDisable = @("RemoteRegistry", "Fax", "Spooler")
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
}

# ============================================================================
# PHASE 3: FTP HARDENING
# ============================================================================
Write-Phase "PHASE 3: FTP HARDENING"

Write-Log "Hardening FTP Server..."

Import-Module WebAdministration -ErrorAction SilentlyContinue

# Backup FTP configuration
$ftpBackup = "$LogDir\ftp_backup_$Timestamp"
New-Item -ItemType Directory -Force -Path $ftpBackup | Out-Null

# Determine FTP type (IIS FTP or standalone)
$iisftp = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

if ($iisftp) {
    Write-Log "IIS FTP Service detected"

    # Backup IIS FTP config
    & "$env:windir\system32\inetsrv\appcmd.exe" add backup "FTP_CCDC_$Timestamp" 2>&1 | Out-Null

    # Disable anonymous authentication
    Set-WebConfigurationProperty -Filter /system.ftpServer/security/authentication/anonymousAuthentication -PSPath IIS:\ -Name enabled -Value $false -ErrorAction SilentlyContinue
    Write-Log "Anonymous FTP authentication disabled"

    # Enable basic authentication (requires SSL ideally)
    Set-WebConfigurationProperty -Filter /system.ftpServer/security/authentication/basicAuthentication -PSPath IIS:\ -Name enabled -Value $true -ErrorAction SilentlyContinue

    # Require SSL for data channel if FTPS is configured
    Write-Log "Consider enabling FTPS (FTP over SSL) for secure transfers"

    # Set FTP logging
    Set-WebConfigurationProperty -Filter /system.ftpServer/log -PSPath IIS:\ -Name logInUTF8 -Value $true -ErrorAction SilentlyContinue

    # Restrict FTP directory
    Write-Log "Review FTP site physical path and permissions"

} else {
    Write-Log "IIS FTP not found, checking for other FTP services..."

    # Check for FileZilla Server or other FTP
    $filezilla = Get-Service -Name "FileZilla Server" -ErrorAction SilentlyContinue
    if ($filezilla) {
        Write-Log "FileZilla Server detected - manual hardening required" "WARN"
    }
}

# Restrict FTP user permissions
Write-Log "Review FTP user accounts and their permissions"

# ============================================================================
# PHASE 4: FIREWALL CONFIGURATION
# ============================================================================
Write-Phase "PHASE 4: FIREWALL CONFIGURATION"

Write-Log "Configuring Windows Firewall for FTP..."

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

$ftpRules = @(
    @{Name="FTP-Control"; Protocol="TCP"; Port=21; Description="FTP Control"},
    @{Name="FTP-Data"; Protocol="TCP"; Port=20; Description="FTP Data"},
    @{Name="FTPS-Implicit"; Protocol="TCP"; Port=990; Description="FTPS Implicit"},
    @{Name="FTP-Passive"; Protocol="TCP"; Port="49152-65535"; Description="FTP Passive Range"},
    @{Name="FTP-RDP"; Protocol="TCP"; Port=3389; Description="RDP Admin"}
)

foreach ($rule in $ftpRules) {
    $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        if ($rule.Port -match "-") {
            # Port range
            $ports = $rule.Port -split "-"
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $ports[0]..$ports[1] -Action Allow -Description $rule.Description | Out-Null
        } else {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port -Action Allow -Description $rule.Description | Out-Null
        }
    }
}

Write-Log "Firewall configured for FTP(21), FTP-DATA(20), FTPS(990), RDP(3389)"

# ============================================================================
# PHASE 5: POST-HARDENING ENUMERATION
# ============================================================================
Write-Phase "PHASE 5: POST-HARDENING ENUMERATION"

$enumPostDir = "$LogDir\enum_post_$Timestamp"
New-Item -ItemType Directory -Force -Path $enumPostDir | Out-Null

systeminfo > "$enumPostDir\systeminfo.txt"
Get-Service | Format-Table * > "$enumPostDir\services.txt"
netstat -ano > "$enumPostDir\netstat.txt"

Write-Log "Post-enumeration saved to $enumPostDir"

# ============================================================================
# SUMMARY
# ============================================================================
Write-Phase "HARDENING COMPLETE"
Write-Host ""
Write-Host "========================================================"
Write-Host "  WINDOWS FTP SERVER HARDENING COMPLETE"
Write-Host "========================================================"
Write-Host ""
Write-Host "NEXT STEPS:"
Write-Host "  1. Verify FTP service is accessible"
Write-Host "  2. Test FTP authentication"
Write-Host "  3. Consider enabling FTPS"
Write-Host "  4. Install Salt minion"
Write-Host ""
Write-Host "SERVICE VERIFICATION:"
Write-Host "  Test-NetConnection -ComputerName localhost -Port 21"
Write-Host "  ftp localhost"
Write-Host ""
Write-Host "========================================================"
