<#
.SYNOPSIS
    Master hardening script for Windows 11 Workstation

.DESCRIPTION
    Runs enumeration, hardening, and post-hardening enumeration for
    Windows 11 workstation. This is a LOW PRIORITY box.

.NOTES
    Target: Windows 11 24H2 - Workstation
    Author: CCDC Team
    Date: 2025-2026
    Version: 1.0

    Services Protected: RDP (3389) only - minimal exposure

.EXAMPLE
    .\master-win-wkst.ps1
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "C:\CCDC\Logs"
$LogFile = "$LogDir\master-win-wkst_$Timestamp.log"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(switch($Level) { "INFO" {"Green"} "WARN" {"Yellow"} "ERROR" {"Red"} default {"White"} })
    Add-Content -Path $LogFile -Value "[$timestamp] [$Level] $Message"
}

function Write-Phase {
    param([string]$Phase)
    Write-Host "`n========== $Phase ==========" -ForegroundColor Cyan
}

Write-Host "========================================================"
Write-Host "  WINDOWS 11 WORKSTATION - MASTER HARDENING SCRIPT"
Write-Host "  Target: Windows 11 24H2 Workstation (LOW PRIORITY)"
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

    # Disable unnecessary services (workstation-specific)
    $servicesToDisable = @(
        "RemoteRegistry",
        "Fax",
        "XblAuthManager",
        "XblGameSave",
        "WMPNetworkSvc",
        "DiagTrack"  # Telemetry
    )
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # Enable Windows Defender features
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue

    # Enable auditing
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
}

# ============================================================================
# PHASE 3: FIREWALL CONFIGURATION
# ============================================================================
Write-Phase "PHASE 3: FIREWALL CONFIGURATION"

Write-Log "Configuring restrictive firewall..."

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Only allow RDP for admin access
$existingRule = Get-NetFirewallRule -DisplayName "WKST-RDP" -ErrorAction SilentlyContinue
if (-not $existingRule) {
    New-NetFirewallRule -DisplayName "WKST-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Description "RDP Admin" | Out-Null
}

Write-Log "Firewall configured: RDP(3389) only"

# ============================================================================
# PHASE 4: POST-HARDENING ENUMERATION
# ============================================================================
Write-Phase "PHASE 4: POST-HARDENING ENUMERATION"

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
Write-Host "  WINDOWS 11 WORKSTATION HARDENING COMPLETE"
Write-Host "========================================================"
Write-Host ""
Write-Host "This is a LOW PRIORITY box (workstation, not scored)"
Write-Host ""
Write-Host "NEXT STEPS:"
Write-Host "  1. Install Salt minion"
Write-Host "  2. Run threat hunting scripts"
Write-Host ""
Write-Host "========================================================"
