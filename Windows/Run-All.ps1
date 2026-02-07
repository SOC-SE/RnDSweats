#--------------------------------------------------------------
# Run-All.ps1 - Orchestrator for Windows competition setup
# Runs: Hardening -> Firewall (in order)
#--------------------------------------------------------------
param(
    [string]$RecoveryPassword = "",
    [switch]$SkipFirewall,
    [switch]$SkipHardening,
    [switch]$FirewallOnly,
    [switch]$HardeningOnly
)

#--------------------------------------------------------------
# Exclude script directory from Defender scanning
# (hardening scripts trigger false positives due to security keywords)
#--------------------------------------------------------------
try {
    Add-MpPreference -ExclusionPath $PSScriptRoot -ErrorAction SilentlyContinue
    Write-Host "[OK] Added Defender exclusion for $PSScriptRoot" -ForegroundColor Green
} catch {}

#--------------------------------------------------------------
# DC Detection
#--------------------------------------------------------------
$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

#--------------------------------------------------------------
# Resolve script paths (all scripts must be in the same dir)
#--------------------------------------------------------------
$hardeningScript    = Join-Path $PSScriptRoot "Start-Hardening.ps1"
$firewallADScript   = Join-Path $PSScriptRoot "firewallAD1.1 (1).ps1"
$firewallBaseScript = Join-Path $PSScriptRoot "Firewallbase1.1 (1).ps1"
$firewallScript = if ($IsDC) { $firewallADScript } else { $firewallBaseScript }

#--------------------------------------------------------------
# Validate switch combinations
#--------------------------------------------------------------
if ($FirewallOnly -and $HardeningOnly) {
    Write-Host "[ERROR] -FirewallOnly and -HardeningOnly are mutually exclusive." -ForegroundColor Red
    exit 1
}

#--------------------------------------------------------------
# Determine what to run
#--------------------------------------------------------------
$runHardening  = (-not $SkipHardening)  -and (-not $FirewallOnly)
$runFirewall   = (-not $SkipFirewall)   -and (-not $HardeningOnly)

#--------------------------------------------------------------
# Validate required scripts exist (only check scripts we'll use)
#--------------------------------------------------------------
$missing = @()
if ($runHardening  -and -not (Test-Path $hardeningScript))  { $missing += $hardeningScript }
if ($runFirewall   -and -not (Test-Path $firewallScript))   { $missing += $firewallScript }

if ($missing.Count -gt 0) {
    Write-Host "[ERROR] Missing required scripts:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

#--------------------------------------------------------------
# Banner
#--------------------------------------------------------------
Write-Host ""
Write-Host "========================================"
Write-Host "|     Windows Competition Run-All      |"
Write-Host "========================================"
Write-Host ""
if ($IsDC) {
    Write-Host "  Detected: Domain Controller" -ForegroundColor Cyan
    Write-Host "  Firewall: firewallAD1.1 (1).ps1" -ForegroundColor Cyan
} else {
    Write-Host "  Detected: Non-DC (workstation/member server)" -ForegroundColor Cyan
    Write-Host "  Firewall: Firewallbase1.1 (1).ps1" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  Phase 1 - Hardening: $(if ($runHardening) {'ON'} else {'SKIP'})"
Write-Host "  Phase 2 - Firewall:  $(if ($runFirewall) {'ON'} else {'SKIP'})"
Write-Host ""

#--------------------------------------------------------------
# Phase 1: Hardening (creates backups before destructive changes)
#--------------------------------------------------------------
if ($runHardening) {
    Write-Host "========================================"
    Write-Host "| Phase 1: Hardening                   |"
    Write-Host "========================================"
    $hardenArgs = @()
    if ($RecoveryPassword -ne "") {
        $hardenArgs += "-RecoveryPassword", $RecoveryPassword
    }
    & $hardeningScript @hardenArgs
}

#--------------------------------------------------------------
# Phase 2: Firewall (backs up current rules then resets)
#--------------------------------------------------------------
if ($runFirewall) {
    Write-Host ""
    Write-Host "========================================"
    Write-Host "| Phase 2: Firewall                    |"
    Write-Host "========================================"
    & $firewallScript
}

#--------------------------------------------------------------
# Summary
#--------------------------------------------------------------
Write-Host ""
Write-Host "========================================"
Write-Host "|            Run-All Complete          |"
Write-Host "========================================"
Write-Host ""
$phases = @()
if ($runHardening)  { $phases += "Hardening" }
if ($runFirewall)   { $phases += "Firewall ($( if ($IsDC) {'AD'} else {'Base'} ))" }
Write-Host "  Completed: $($phases -join ' -> ')" -ForegroundColor Green
Write-Host ""
if ($runHardening) {
    Write-Host "  Consider rebooting to apply all changes." -ForegroundColor Yellow
}
