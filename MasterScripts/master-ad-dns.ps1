<#
.SYNOPSIS
    Master hardening script for Windows AD/DNS Server

.DESCRIPTION
    Runs enumeration, hardening, and post-hardening enumeration for
    Windows Server 2019 Domain Controller with AD and DNS services.

    Workflow:
    1. Initial enumeration
    2. Quick hardening (quickHarden.ps1)
    3. AD-specific hardening
    4. DNS hardening
    5. Firewall configuration
    6. Post-hardening enumeration

.NOTES
    Target: Windows Server 2019 - AD/DNS Domain Controller
    Author: CCDC Team
    Date: 2025-2026
    Version: 1.0

    Services Protected: AD (389, 636), DNS (53), Kerberos (88), LDAP, RPC

.EXAMPLE
    .\master-ad-dns.ps1
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "C:\CCDC\Logs"
$LogFile = "$LogDir\master-ad-dns_$Timestamp.log"

# Create log directory
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Logging functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $(switch($Level) { "INFO" {"Green"} "WARN" {"Yellow"} "ERROR" {"Red"} default {"White"} })
    Add-Content -Path $LogFile -Value $logMessage
}

function Write-Phase {
    param([string]$Phase)
    Write-Host ""
    Write-Host "========== $Phase ==========" -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "`n========== $Phase =========="
}

Write-Host "========================================================"
Write-Host "  WINDOWS AD/DNS SERVER - MASTER HARDENING SCRIPT"
Write-Host "  Target: Windows Server 2019 Domain Controller"
Write-Host "  Time: $(Get-Date)"
Write-Host "========================================================"
Write-Host ""

# ============================================================================
# PHASE 1: INITIAL ENUMERATION
# ============================================================================
Write-Phase "PHASE 1: INITIAL ENUMERATION"
Write-Log "Capturing pre-hardening system state..."

# Basic enumeration
$enumDir = "$LogDir\enum_pre_$Timestamp"
New-Item -ItemType Directory -Force -Path $enumDir | Out-Null

# System info
systeminfo > "$enumDir\systeminfo.txt"
Get-LocalUser | Format-Table * > "$enumDir\local_users.txt"
Get-LocalGroup | Format-Table * > "$enumDir\local_groups.txt"
Get-Process | Format-Table * > "$enumDir\processes.txt"
Get-Service | Format-Table * > "$enumDir\services.txt"
netstat -ano > "$enumDir\netstat.txt"
Get-ScheduledTask | Format-Table * > "$enumDir\scheduled_tasks.txt"

# AD-specific
if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
    Get-ADUser -Filter * -Properties * | Export-Csv "$enumDir\ad_users.csv" -NoTypeInformation
    Get-ADGroup -Filter * | Export-Csv "$enumDir\ad_groups.csv" -NoTypeInformation
    Get-ADComputer -Filter * | Export-Csv "$enumDir\ad_computers.csv" -NoTypeInformation
    Get-GPO -All | Export-Csv "$enumDir\gpos.csv" -NoTypeInformation
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
    Write-Log "quickHarden.ps1 not found, applying manual hardening..." "WARN"

    # Disable unnecessary services
    $servicesToDisable = @("RemoteRegistry", "Spooler", "Fax")
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # Enable audit policies
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
}

# ============================================================================
# PHASE 3: AD-SPECIFIC HARDENING
# ============================================================================
Write-Phase "PHASE 3: AD-SPECIFIC HARDENING"

Write-Log "Hardening Active Directory..."

# Check for AD module
if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {

    # Disable Guest account
    Disable-ADAccount -Identity "Guest" -ErrorAction SilentlyContinue
    Write-Log "Disabled Guest account"

    # Set password policies (if not already set by GPO)
    Write-Log "Password policies should be configured via Group Policy"

    # Check for privileged accounts with weak settings
    $adminGroup = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
    Write-Log "Domain Admins count: $($adminGroup.Count)"

    # List accounts that don't require Kerberos pre-authentication (potential issue)
    $noPreAuth = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -ErrorAction SilentlyContinue
    if ($noPreAuth) {
        Write-Log "WARNING: Accounts without Kerberos pre-auth: $($noPreAuth.Count)" "WARN"
    }

    # Check for AdminSDHolder protected accounts
    Write-Log "Review AdminSDHolder protected accounts manually"
}

# ============================================================================
# PHASE 4: DNS HARDENING
# ============================================================================
Write-Phase "PHASE 4: DNS HARDENING"

Write-Log "Hardening DNS Server..."

if (Get-Command Get-DnsServer -ErrorAction SilentlyContinue) {
    # Disable recursion if this is authoritative only
    # Set-DnsServerRecursion -Enable $false  # Uncomment if appropriate

    # Secure DNS
    $dnsServer = Get-DnsServer -ErrorAction SilentlyContinue
    Write-Log "DNS Server configuration captured"

    # Enable DNS logging
    Set-DnsServerDiagnostics -All $true -ErrorAction SilentlyContinue
    Write-Log "DNS diagnostics enabled"
} else {
    Write-Log "DNS Server module not available" "WARN"
}

# ============================================================================
# PHASE 5: FIREWALL CONFIGURATION
# ============================================================================
Write-Phase "PHASE 5: FIREWALL CONFIGURATION"

Write-Log "Configuring Windows Firewall for AD/DNS..."

# Enable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block inbound by default
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Allow AD/DNS services
$adRules = @(
    @{Name="AD-DNS-UDP"; Protocol="UDP"; Port=53; Description="DNS"},
    @{Name="AD-DNS-TCP"; Protocol="TCP"; Port=53; Description="DNS"},
    @{Name="AD-Kerberos"; Protocol="TCP"; Port=88; Description="Kerberos"},
    @{Name="AD-Kerberos-UDP"; Protocol="UDP"; Port=88; Description="Kerberos"},
    @{Name="AD-LDAP"; Protocol="TCP"; Port=389; Description="LDAP"},
    @{Name="AD-LDAPS"; Protocol="TCP"; Port=636; Description="LDAPS"},
    @{Name="AD-GC"; Protocol="TCP"; Port=3268; Description="Global Catalog"},
    @{Name="AD-GCS"; Protocol="TCP"; Port=3269; Description="Global Catalog SSL"},
    @{Name="AD-RPC"; Protocol="TCP"; Port=135; Description="RPC Endpoint Mapper"},
    @{Name="AD-NetBIOS"; Protocol="TCP"; Port=139; Description="NetBIOS"},
    @{Name="AD-SMB"; Protocol="TCP"; Port=445; Description="SMB"},
    @{Name="AD-RDP"; Protocol="TCP"; Port=3389; Description="RDP"}
)

foreach ($rule in $adRules) {
    $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port -Action Allow -Description $rule.Description | Out-Null
    }
}

Write-Log "Firewall configured for AD/DNS services"

# ============================================================================
# PHASE 6: POST-HARDENING ENUMERATION
# ============================================================================
Write-Phase "PHASE 6: POST-HARDENING ENUMERATION"

$enumPostDir = "$LogDir\enum_post_$Timestamp"
New-Item -ItemType Directory -Force -Path $enumPostDir | Out-Null

systeminfo > "$enumPostDir\systeminfo.txt"
Get-Service | Format-Table * > "$enumPostDir\services.txt"
Get-NetFirewallRule -Enabled True | Format-Table * > "$enumPostDir\firewall_rules.txt"
netstat -ano > "$enumPostDir\netstat.txt"

Write-Log "Post-enumeration saved to $enumPostDir"

# ============================================================================
# SUMMARY
# ============================================================================
Write-Phase "HARDENING COMPLETE"
Write-Host ""
Write-Host "========================================================"
Write-Host "  WINDOWS AD/DNS SERVER HARDENING COMPLETE"
Write-Host "========================================================"
Write-Host ""
Write-Host "Logs saved to: $LogDir"
Write-Host ""
Write-Host "NEXT STEPS:"
Write-Host "  1. Change all passwords (including KRBTGT twice)"
Write-Host "  2. Review AD users and groups for anomalies"
Write-Host "  3. Install Salt minion"
Write-Host "  4. Run threat hunting scripts"
Write-Host ""
Write-Host "SERVICE VERIFICATION:"
Write-Host "  dcdiag /v"
Write-Host "  nltest /dsgetdc:$env:USERDNSDOMAIN"
Write-Host "  nslookup $env:COMPUTERNAME"
Write-Host ""
Write-Host "========================================================"
