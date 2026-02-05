#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disables SMBv3 encryption and enables audit policies for IDS visibility.

.DESCRIPTION
    SMBv3 encryption blinds network IDS (Zeek, BZAR, Suricata) to all DCE-RPC
    operations over named pipes — PsExec, WMIExec, ATExec, secretsdump, DCSync.

    Two-layer defense:
      Layer 1 (Network): Disable SMB encryption so Zeek sees DCE-RPC in named pipes.
        - Works for Windows-to-Windows lateral movement (both sides follow GPO).
        - Third-party clients (Impacket from Linux) may still use encryption
          regardless of server settings — that's what Layer 2 catches.
      Layer 2 (Host): Enable audit policies so Wazuh/Splunk sees Events 7045,
        4697, 4698, 4662, 4769, 5145 etc. directly on the endpoint.
        - Works regardless of encryption. Primary defense against Impacket.

    Run this on EVERY Windows host in the first 15 minutes of competition.

.NOTES
    Samuel Brucker 2026
    Part of Zeek Red Team Detection Suite v1.4.0
#>

param (
    [switch]$SkipSMB,
    [switch]$SkipAudit,
    [switch]$Quiet
)

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    if ($Quiet) { return }
    $color = switch ($Type) {
        "OK"    { "Green" }
        "WARN"  { "Yellow" }
        "ERR"   { "Red" }
        default { "Cyan" }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
}

# ============================================================
# 1. DISABLE SMB3 ENCRYPTION, ENFORCE SIGNING
# ============================================================
if (-not $SkipSMB) {
    Write-Status "Configuring SMB: disable encryption, enforce signing"

    # Server-side: don't encrypt, don't reject unencrypted, require signing
    Set-SmbServerConfiguration `
        -EncryptData $false `
        -RejectUnencryptedAccess $false `
        -RequireSecuritySignature $true `
        -Confirm:$false

    # Client-side: don't require encryption, require signing
    try {
        Set-SmbClientConfiguration `
            -RequireEncryption $false `
            -RequireSecuritySignature $true `
            -Confirm:$false
    } catch {
        # RequireEncryption parameter not available on older Windows versions
        Set-SmbClientConfiguration `
            -RequireSecuritySignature $true `
            -Confirm:$false
    }

    # Disable per-share encryption overrides
    Get-SmbShare | Where-Object { $_.EncryptData -eq $true } | ForEach-Object {
        Set-SmbShare -Name $_.Name -EncryptData $false -Confirm:$false
        Write-Status "Disabled encryption on share: $($_.Name)" "WARN"
    }

    # Verify
    $srv = Get-SmbServerConfiguration
    Write-Status "SMB Server: EncryptData=$($srv.EncryptData), RejectUnencrypted=$($srv.RejectUnencryptedAccess), RequireSigning=$($srv.RequireSecuritySignature)" "OK"
}

# ============================================================
# 2. ENABLE ADVANCED AUDIT POLICIES
# ============================================================
if (-not $SkipAudit) {
    Write-Status "Configuring advanced audit policies for lateral movement detection"

    # Service creation (PsExec, svcctl)
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null

    # Logon events (Type 3 = network, Type 10 = RDP)
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null

    # Process creation (WMI/DCOM child processes, command lines)
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null

    # Share access (admin shares C$, ADMIN$, IPC$)
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable | Out-Null

    # Directory service (DCSync - Event 4662)
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null

    # Kerberos (Kerberoasting - Event 4769)
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null

    # Named pipe access (PetitPotam, PrintNightmare - Event 5145)
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null

    # Scheduled task events (ATExec - Event 4698/4699)
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null

    Write-Status "Audit policies configured" "OK"

    # ============================================================
    # 3. ENABLE COMMAND-LINE IN PROCESS CREATION EVENTS
    # ============================================================
    Write-Status "Enabling command-line logging in process creation events"

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

    Write-Status "Process command-line logging enabled (Event 4688)" "OK"

    # ============================================================
    # 4. ENABLE POWERSHELL SCRIPT BLOCK LOGGING
    # ============================================================
    Write-Status "Enabling PowerShell script block logging"

    $psRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psRegPath)) {
        New-Item -Path $psRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $psRegPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

    Write-Status "PowerShell script block logging enabled (Event 4104)" "OK"

    # ============================================================
    # 5. ENABLE LDAP DIAGNOSTICS ON DCS (if this is a DC)
    # ============================================================
    $isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
    if ($isDC) {
        Write-Status "Domain Controller detected - enabling LDAP diagnostics"

        $ntdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        if (Test-Path $ntdsPath) {
            # Level 5 = verbose LDAP query logging (Event 1644)
            Set-ItemProperty -Path $ntdsPath -Name "15 Field Engineering" -Value 5 -Type DWord
            Write-Status "LDAP expensive query logging enabled (Event 1644)" "OK"
        }
    }
}

# ============================================================
# SUMMARY
# ============================================================
Write-Status ""
Write-Status "========================================" "OK"
Write-Status " Network Visibility Configuration Done  " "OK"
Write-Status "========================================" "OK"
Write-Status ""
Write-Status "LAYER 1 — Network (Zeek/BZAR):"
Write-Status "  SMB encryption OFF, signing ON"
Write-Status "  Windows-to-Windows lateral movement now visible to Zeek"
Write-Status "  NOTE: Impacket from Linux still uses encryption — Layer 2 catches that"
Write-Status ""
Write-Status "LAYER 2 — Host (Wazuh/Splunk) events now generated:"
Write-Status "  4624/4625  - Logon success/failure (Type 3 = network)"
Write-Status "  4662       - DS object access (DCSync detection)"
Write-Status "  4688       - Process creation with command line"
Write-Status "  4697/7045  - Service installation (PsExec)"
Write-Status "  4698/4699  - Scheduled task create/delete (ATExec)"
Write-Status "  4769       - Kerberos TGS request (Kerberoasting)"
Write-Status "  5140/5145  - Share access / object check (admin shares, named pipes)"
Write-Status "  4104       - PowerShell script blocks"
Write-Status ""
Write-Status "Ensure Wazuh/Splunk UF collects: Security, System, Sysmon, PowerShell, WMI-Activity, TaskScheduler" "WARN"
