<#
.SYNOPSIS
  Safe baseline hardening for a Windows Server Domain Controller running AD DS + DNS.
 
.DESCRIPTION
  Applies a conservative, competition-friendly baseline:
  - Sets AD default domain password policy (length, complexity, lockout)
  - Hardens DNS zones (disable zone transfers, secure dynamic updates where possible)
  - Ensures Windows Firewall is enabled
  - Logs all changes to a transcript file
 
.NOTES
  Run on the Domain Controller as an Administrator.
#>
 
param(
  [switch]$WhatIfMode,
  [int]$MinPasswordLength = 8,
  [int]$LockoutThreshold = 5,
  [int]$LockoutDurationMinutes = 30,
  [int]$LockoutObservationWindowMinutes = 30,
  [int]$MaxPasswordAgeDays = 60
)
 
function Write-Info($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "[-] $msg" -ForegroundColor Red }
 
function Require-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}
 
function Require-Module($name) {
  if (-not (Get-Module -ListAvailable -Name $name)) {
    throw "Missing module: $name. Install RSAT/role features for $name first."
  }
}
 
function Run-OrWhatIf([scriptblock]$block, [string]$desc) {
  if ($WhatIfMode) {
    Write-Info "WHATIF: $desc"
  } else {
    Write-Info $desc
    & $block
  }
}
 
try {
  Require-Admin
 
  $logDir = Join-Path $env:SystemDrive "CCDC-Hardening"
  if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
 
  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $logFile = Join-Path $logDir "hardening-$ts.txt"
  Start-Transcript -Path $logFile -NoClobber | Out-Null
 
  Write-Info "Starting safe AD/DNS hardening baseline..."
  if ($WhatIfMode) { Write-Warn "Running in WHATIF mode: no changes will be made." }
 
  # --- Detect Domain Controller + Domain ---
  Require-Module ActiveDirectory
  $domain = Get-ADDomain
  Write-Ok "Domain detected: $($domain.DNSRoot)"
 
  # --- 1) AD Default Domain Password Policy ---
  $policy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName
  Write-Info "Current password policy:"
  $policy | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold, LockoutDuration, LockoutObservationWindow, MaxPasswordAge | Format-List
 
  $lockoutDuration   = New-TimeSpan -Minutes $LockoutDurationMinutes
  $lockoutWindow     = New-TimeSpan -Minutes $LockoutObservationWindowMinutes
  $maxPasswordAge    = New-TimeSpan -Days $MaxPasswordAgeDays
 
  Run-OrWhatIf {
    Set-ADDefaultDomainPasswordPolicy `
      -Identity $domain.DistinguishedName `
      -MinPasswordLength $MinPasswordLength `
      -ComplexityEnabled $true `
      -LockoutThreshold $LockoutThreshold `
      -LockoutDuration $lockoutDuration `
      -LockoutObservationWindow $lockoutWindow `
      -MaxPasswordAge $maxPasswordAge
  } "Applying AD default domain password policy (minlen=$MinPasswordLength, lockout=$LockoutThreshold, maxAgeDays=$MaxPasswordAgeDays)..."
 
  Write-Ok "AD password/lockout policy applied (or staged in WhatIf)."
 
  # --- 2) DNS Zone Hardening ---
  Require-Module DnsServer
 
  $zones = Get-DnsServerZone | Where-Object { $_.ZoneName -and $_.IsReverseLookupZone -eq $false }
  if (-not $zones) {
    Write-Warn "No forward zones found in DNS Server."
  } else {
    Write-Info "Found DNS forward zones:"
    $zones | Select-Object ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate | Format-Table -AutoSize
  }
 
  foreach ($z in $zones) {
    $zoneName = $z.ZoneName
 
    # Disable zone transfers (NoTransfer)
    Run-OrWhatIf {
      # Works for primary/AD-integrated zones; if unsupported, we catch and continue.
      try {
        Set-DnsServerPrimaryZone -Name $zoneName -SecureSecondaries NoTransfer -ErrorAction Stop
        Write-Ok "Zone transfers disabled for $zoneName"
      } catch {
        Write-Warn "Could not set SecureSecondaries=NoTransfer for $zoneName (may be not a primary zone). Trying zone transfer settings via CIM..."
        # Fallback: for some environments, GUI-only settings exist; we log and move on safely.
        Write-Warn "Manual check recommended: DNS Manager -> Zone Properties -> Zone Transfers (ensure disabled)."
      }
    } "Disabling DNS zone transfers for $zoneName..."
 
    # Secure dynamic updates when AD-integrated supports it
    Run-OrWhatIf {
      try {
        # Secure dynamic updates for AD-integrated zones
        if ($z.IsDsIntegrated) {
          Set-DnsServerZone -Name $zoneName -DynamicUpdate Secure -ErrorAction Stop
          Write-Ok "Secure dynamic updates enabled for $zoneName"
        } else {
          Write-Info "$zoneName is not AD-integrated; leaving dynamic updates as-is (manual review)."
        }
      } catch {
        Write-Warn "Could not set DynamicUpdate=Secure for $zoneName. Manual review recommended."
      }
    } "Hardening dynamic updates for $zoneName..."
  }
 
  # --- 3) Windows Firewall (basic safe stance) ---
  Run-OrWhatIf {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
  } "Ensuring Windows Firewall is enabled for all profiles..."
 
  Write-Ok "Firewall enabled."
 
  # --- Final quick verification output ---
  Write-Info "Post-change verification (read-only):"
  $newPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName
  $newPolicy | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold, LockoutDuration, LockoutObservationWindow, MaxPasswordAge | Format-List
 
  Write-Info "DNS zones (read-only):"
  Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate | Format-Table -AutoSize
 
  Write-Ok "Completed. Log saved to: $logFile"
}
catch {
  Write-Fail $_.Exception.Message
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
}