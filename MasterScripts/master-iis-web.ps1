<#
.SYNOPSIS
    Master hardening script for Windows IIS Web Server

.DESCRIPTION
    Runs enumeration, hardening, and post-hardening enumeration for
    Windows Server 2019 with IIS web services.

.NOTES
    Target: Windows Server 2019 - IIS Web Server
    Author: CCDC Team
    Date: 2025-2026
    Version: 1.0

    Services Protected: HTTP (80), HTTPS (443), RDP (3389)

.EXAMPLE
    .\master-iis-web.ps1
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "C:\CCDC\Logs"
$LogFile = "$LogDir\master-iis-web_$Timestamp.log"

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
Write-Host "  WINDOWS IIS WEB SERVER - MASTER HARDENING SCRIPT"
Write-Host "  Target: Windows Server 2019 with IIS"
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

# IIS-specific enumeration
if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
    Get-Website | Format-Table * > "$enumDir\iis_websites.txt"
    Get-WebApplication | Format-Table * > "$enumDir\iis_applications.txt"
    Get-WebBinding | Format-Table * > "$enumDir\iis_bindings.txt"
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

    # Disable unnecessary services
    $servicesToDisable = @("RemoteRegistry", "Fax", "XblAuthManager", "XblGameSave")
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # Enable auditing
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
}

# ============================================================================
# PHASE 3: IIS HARDENING
# ============================================================================
Write-Phase "PHASE 3: IIS HARDENING"

Write-Log "Hardening IIS Web Server..."

# Import WebAdministration module
Import-Module WebAdministration -ErrorAction SilentlyContinue

if (Get-Command Get-Website -ErrorAction SilentlyContinue) {

    # Backup IIS configuration
    $iisBackup = "$LogDir\iis_backup_$Timestamp"
    New-Item -ItemType Directory -Force -Path $iisBackup | Out-Null
    & "$env:windir\system32\inetsrv\appcmd.exe" add backup "CCDC_$Timestamp" 2>&1 | Out-Null
    Write-Log "IIS configuration backed up"

    # Remove default IIS headers
    Write-Log "Removing version headers..."

    # Disable directory browsing
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath IIS:\ -Name enabled -Value $false -ErrorAction SilentlyContinue
    Write-Log "Directory browsing disabled"

    # Remove X-Powered-By header
    Remove-WebConfigurationProperty -PSPath IIS:\ -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name='X-Powered-By'} -ErrorAction SilentlyContinue

    # Add security headers
    $securityHeaders = @(
        @{Name="X-Content-Type-Options"; Value="nosniff"},
        @{Name="X-Frame-Options"; Value="SAMEORIGIN"},
        @{Name="X-XSS-Protection"; Value="1; mode=block"}
    )

    foreach ($header in $securityHeaders) {
        Add-WebConfigurationProperty -PSPath IIS:\ -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name=$header.Name; value=$header.Value} -ErrorAction SilentlyContinue
    }
    Write-Log "Security headers added"

    # Disable unnecessary ISAPI filters and handlers
    Write-Log "Review ISAPI filters manually for unnecessary handlers"

    # Set application pool identity
    Get-ChildItem IIS:\AppPools | ForEach-Object {
        Set-ItemProperty "IIS:\AppPools\$($_.Name)" -Name processModel.identityType -Value 4  # ApplicationPoolIdentity
    }
    Write-Log "Application pool identities configured"

} else {
    Write-Log "IIS WebAdministration module not available" "WARN"
}

# ============================================================================
# PHASE 4: FIREWALL CONFIGURATION
# ============================================================================
Write-Phase "PHASE 4: FIREWALL CONFIGURATION"

Write-Log "Configuring Windows Firewall for IIS..."

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Allow web services
$webRules = @(
    @{Name="IIS-HTTP"; Protocol="TCP"; Port=80; Description="HTTP"},
    @{Name="IIS-HTTPS"; Protocol="TCP"; Port=443; Description="HTTPS"},
    @{Name="IIS-RDP"; Protocol="TCP"; Port=3389; Description="RDP Admin"}
)

foreach ($rule in $webRules) {
    $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port -Action Allow -Description $rule.Description | Out-Null
    }
}

Write-Log "Firewall configured for HTTP(80), HTTPS(443), RDP(3389)"

# ============================================================================
# PHASE 5: POST-HARDENING ENUMERATION
# ============================================================================
Write-Phase "PHASE 5: POST-HARDENING ENUMERATION"

$enumPostDir = "$LogDir\enum_post_$Timestamp"
New-Item -ItemType Directory -Force -Path $enumPostDir | Out-Null

systeminfo > "$enumPostDir\systeminfo.txt"
Get-Service | Format-Table * > "$enumPostDir\services.txt"
netstat -ano > "$enumPostDir\netstat.txt"

if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
    Get-Website | Format-Table * > "$enumPostDir\iis_websites.txt"
}

Write-Log "Post-enumeration saved to $enumPostDir"

# ============================================================================
# SUMMARY
# ============================================================================
Write-Phase "HARDENING COMPLETE"
Write-Host ""
Write-Host "========================================================"
Write-Host "  WINDOWS IIS WEB SERVER HARDENING COMPLETE"
Write-Host "========================================================"
Write-Host ""
Write-Host "IIS Backup: $env:windir\system32\inetsrv\backup\CCDC_$Timestamp"
Write-Host ""
Write-Host "NEXT STEPS:"
Write-Host "  1. Verify websites are accessible"
Write-Host "  2. Review application code for vulnerabilities"
Write-Host "  3. Install Salt minion"
Write-Host ""
Write-Host "SERVICE VERIFICATION:"
Write-Host "  Invoke-WebRequest -Uri http://localhost -UseBasicParsing"
Write-Host "  iisreset /status"
Write-Host ""
Write-Host "========================================================"
