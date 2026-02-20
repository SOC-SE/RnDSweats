<#
.SYNOPSIS
    Installs the Salt Minion on Windows using the official Broadcom MSI.

.DESCRIPTION
    Automates Salt Minion installation for Salt-GUI:
    - Verifies Administrator privileges
    - Supports interactive and non-interactive modes
    - Detects OS Architecture (64-bit vs 32-bit)
    - Downloads the correct MSI from the Broadcom repository
    - Performs a quiet install with logging
    - Configures Windows Firewall exceptions
    - Starts the service

.PARAMETER MasterIP
    The IP address or hostname of the Salt Master. Default: 172.20.242.20

.PARAMETER MinionID
    The unique identifier for this minion. Default: system hostname

.PARAMETER SaltVersion
    The Salt version to install. Default: 3007.13

.PARAMETER NonInteractive
    Run without prompts (requires MasterIP parameter)

.EXAMPLE
    # Interactive mode
    .\Install-SaltMinion.ps1

.EXAMPLE
    # Non-interactive mode
    .\Install-SaltMinion.ps1 -MasterIP "172.20.242.20" -MinionID "win-server01" -NonInteractive

.EXAMPLE
    # Specify custom Salt version
    .\Install-SaltMinion.ps1 -MasterIP "10.0.0.1" -SaltVersion "3007.13" -NonInteractive

.NOTES
    Based on original script by Samuel Brucker 2025-2026
    Modified for Salt-GUI integration
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$MasterIP = "",

    [Parameter(Mandatory=$false)]
    [string]$MinionID = "",

    [Parameter(Mandatory=$false)]
    [string]$SaltVersion = "3007.13",

    [Parameter(Mandatory=$false)]
    [switch]$NonInteractive
)

# --- Configuration ---
$DEFAULT_MASTER_IP = "172.20.242.20"
$ErrorActionPreference = "Stop"

# --- Functions ---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $colors = @{
        "INFO" = "Green"
        "WARN" = "Yellow"
        "ERROR" = "Red"
        "DEBUG" = "Cyan"
    }
    $color = $colors[$Level]
    if (-not $color) { $color = "White" }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$Default
    )

    if ($NonInteractive) {
        return $Default
    }

    $input = Read-Host -Prompt "$Prompt [Default: $Default]"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    }
    return $input
}

function Test-DomainController {
    $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
    # DomainRole: 4 = Backup DC, 5 = Primary DC
    return ($null -ne $cs) -and ($cs.DomainRole -ge 4)
}

function Test-SaltMinionInstalled {
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Uninstall-ExistingMinion {
    Write-Log "Removing existing Salt Minion to ensure clean install..." "WARN"

    # Stop the service first
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name "salt-minion" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # Find and uninstall via MSI product code
    $product = Get-WmiObject Win32_Product | Where-Object { $_.Name -like '*Salt Minion*' }
    if ($product) {
        Write-Log "Uninstalling: $($product.Name) $($product.Version)"
        $result = $product.Uninstall()
        if ($result.ReturnValue -eq 0) {
            Write-Log "Previous version uninstalled successfully"
        } else {
            Write-Log "Uninstall returned code: $($result.ReturnValue)" "WARN"
        }
        Start-Sleep -Seconds 3
    } else {
        # Fallback: just stop the service if WMI can't find the product
        Write-Log "Could not find MSI product entry, stopping service only" "WARN"
    }
}

function Stop-ExistingMinion {
    $service = Get-Service -Name "salt-minion" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Log "Stopping existing Salt Minion service..." "WARN"
        Stop-Service -Name "salt-minion" -Force
        Start-Sleep -Seconds 2
    }
}

function Test-PreFlightChecks {
    param(
        [string]$MasterIP
    )

    Write-Log "Running pre-flight checks..."
    $failed = $false

    # 1. PowerShell Execution Policy - check if GPO blocks script execution
    $machinePolicy = Get-ExecutionPolicy -Scope MachinePolicy
    $userPolicy = Get-ExecutionPolicy -Scope UserPolicy
    if ($machinePolicy -ne 'Undefined' -and $machinePolicy -ne 'Bypass' -and $machinePolicy -ne 'Unrestricted') {
        Write-Log "GPO enforces execution policy: $machinePolicy (MachinePolicy scope)" "ERROR"
        Write-Log "  Fix: Ask domain admin to allow scripts, or run:" "WARN"
        Write-Log "  powershell.exe -ExecutionPolicy Bypass -File $($MyInvocation.ScriptName)" "WARN"
        $failed = $true
    } elseif ($userPolicy -ne 'Undefined' -and $userPolicy -ne 'Bypass' -and $userPolicy -ne 'Unrestricted') {
        Write-Log "GPO enforces execution policy: $userPolicy (UserPolicy scope)" "WARN"
    }

    # 2. PowerShell Language Mode - Constrained Language blocks .NET calls
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        Write-Log "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode" "ERROR"
        Write-Log "  This is typically caused by Device Guard/WDAC policy" "WARN"
        Write-Log "  Salt Minion installation requires FullLanguage mode" "WARN"
        $failed = $true
    }

    # 3. MSI installer restrictions via GPO
    $msiPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue
    if ($msiPolicy) {
        # DisableMSI: 0=never, 1=non-managed only, 2=always
        if ($msiPolicy.DisableMSI -eq 2) {
            Write-Log "GPO blocks all MSI installations (DisableMSI=2)" "ERROR"
            Write-Log "  Fix: Domain admin must set 'Disable Windows Installer' to 'Never'" "WARN"
            $failed = $true
        } elseif ($msiPolicy.DisableMSI -eq 1) {
            Write-Log "GPO restricts non-managed MSI installations" "WARN"
            Write-Log "  Installation may still work for administrators" "WARN"
        }
    }

    # 4. Windows Defender - check if it could quarantine Salt
    $defender = Get-MpPreference -ErrorAction SilentlyContinue
    if ($defender -and -not $defender.DisableRealtimeMonitoring) {
        $saltPath = "C:\Program Files\Salt Project\Salt"
        $excluded = $false
        if ($defender.ExclusionPath) {
            foreach ($exc in $defender.ExclusionPath) {
                if ($saltPath.StartsWith($exc.TrimEnd('\')) -or $exc.TrimEnd('\').StartsWith($saltPath)) {
                    $excluded = $true
                    break
                }
            }
        }
        if (-not $excluded) {
            Write-Log "Windows Defender real-time protection is active" "WARN"
            Write-Log "  Salt may be flagged as a remote admin tool. Adding exclusion..." "WARN"
            try {
                $existing = @()
                if ($defender.ExclusionPath) { $existing = @($defender.ExclusionPath) }
                $newExclusions = $existing + @($saltPath, "C:\ProgramData\Salt Project\Salt") | Select-Object -Unique
                Set-MpPreference -ExclusionPath $newExclusions -ErrorAction Stop
                Write-Log "  Defender exclusions added for Salt directories"
            } catch {
                Write-Log "  Could not add Defender exclusion (may need manual GPO change)" "WARN"
                Write-Log "  If install fails, manually exclude: $saltPath" "WARN"
            }
        }
    }

    # 5. Network proxy detection
    $proxyEnabled = $false
    $winHttpProxy = netsh winhttp show proxy 2>&1 | Out-String
    if ($winHttpProxy -match 'Proxy Server\(s\)\s*:\s*\S') {
        Write-Log "System proxy detected (WinHTTP): check netsh winhttp show proxy" "WARN"
        Write-Log "  Download may fail if proxy requires authentication" "WARN"
        $proxyEnabled = $true
    }
    $ieProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ieProxy -and $ieProxy.ProxyEnable -eq 1) {
        Write-Log "IE/User proxy enabled: $($ieProxy.ProxyServer)" "WARN"
        $proxyEnabled = $true
    }

    # 6. Network connectivity to Salt Master
    $portTest = Test-NetConnection -ComputerName $MasterIP -Port 4506 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if (-not $portTest.TcpTestSucceeded) {
        Write-Log "Cannot reach Salt Master at ${MasterIP}:4506" "ERROR"
        Write-Log "  Check firewall rules and network connectivity" "WARN"
        # Also test 4505
        $pubTest = Test-NetConnection -ComputerName $MasterIP -Port 4505 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if (-not $pubTest.TcpTestSucceeded) {
            Write-Log "  Also cannot reach ${MasterIP}:4505" "ERROR"
        }
        $failed = $true
    } else {
        Write-Log "Salt Master reachable at ${MasterIP}:4506"
    }

    # 7. Firewall GPO override check - local rules may be ignored
    $domainProfile = Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue
    if ($domainProfile -and $domainProfile.Enabled) {
        $gpoRules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.PolicyStoreSource -eq 'GroupPolicy' } |
            Measure-Object
        if ($gpoRules.Count -gt 0) {
            Write-Log "GPO firewall rules detected ($($gpoRules.Count) rules)" "WARN"
            Write-Log "  Local firewall rules may be overridden by domain policy" "WARN"
            Write-Log "  Ensure Salt ports 4505/4506 outbound are allowed in GPO" "WARN"
        }
    }

    # 8. AppLocker check
    try {
        $appLocker = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $msiRules = $appLocker.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Msi' }
        $exeRules = $appLocker.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' }
        if ($msiRules -and $msiRules.Count -gt 0) {
            Write-Log "AppLocker MSI rules are active ($($msiRules.Count) rules)" "WARN"
            Write-Log "  MSI installation may be blocked if not whitelisted" "WARN"
        }
        if ($exeRules -and $exeRules.Count -gt 0) {
            Write-Log "AppLocker EXE rules are active ($($exeRules.Count) rules)" "WARN"
            Write-Log "  salt-minion.exe may be blocked after installation" "WARN"
        }
    } catch {
        # AppLocker not configured - this is fine
    }

    if ($failed) {
        Write-Log "Pre-flight checks found blocking issues (see above)" "ERROR"
        return $false
    }

    Write-Log "Pre-flight checks passed"
    return $true
}

function Get-SaltInstallerUrl {
    param(
        [string]$Version
    )

    if ([Environment]::Is64BitOperatingSystem) {
        Write-Log "Detected 64-bit Operating System"
        $arch = "AMD64"
    } else {
        Write-Log "Detected 32-bit Operating System"
        $arch = "x86"
    }

    $fileName = "Salt-Minion-$Version-Py3-$arch.msi"
    $url = "https://packages.broadcom.com/artifactory/saltproject-generic/windows/$Version/$fileName"

    return @{
        Url = $url
        FileName = $fileName
        Arch = $arch
    }
}

function Install-SaltMinion {
    param(
        [string]$InstallerPath,
        [string]$MasterIP,
        [string]$MinionID,
        [string]$LogPath
    )

    Write-Log "Installing Salt Minion..."
    Write-Log "  Master: $MasterIP"
    Write-Log "  Minion ID: $MinionID"

    $msiArgs = @(
        "/i", "`"$InstallerPath`"",
        "/quiet",
        "/norestart",
        "/log", "`"$LogPath`"",
        "MASTER=$MasterIP",
        "MINION_ID=$MinionID",
        "START_MINION=1"
    )

    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        Write-Log "Installer exited with code: $($process.ExitCode)" "ERROR"
        Write-Log "Check log file: $LogPath" "WARN"
        throw "Installation failed with exit code $($process.ExitCode)"
    }

    Write-Log "Installation completed successfully"
}

function Set-FirewallRules {
    Write-Log "Configuring Windows Firewall..."

    # Common Salt Minion paths (3007+ installs to root, older to bin/)
    $saltPaths = @(
        "C:\Program Files\Salt Project\Salt\salt-minion.exe",
        "C:\Program Files\Salt Project\Salt\bin\salt-minion.exe",
        "C:\salt\salt-minion.exe",
        "C:\salt\bin\salt-minion.exe"
    )

    $saltExe = $null
    foreach ($path in $saltPaths) {
        if (Test-Path $path) {
            $saltExe = $path
            break
        }
    }

    if ($saltExe) {
        # Remove existing rules if any
        Get-NetFirewallRule -DisplayName "Salt Minion*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        # Add inbound rule for salt-minion
        New-NetFirewallRule -DisplayName "Salt Minion" `
            -Direction Inbound `
            -Program $saltExe `
            -Action Allow `
            -Profile Any `
            -Description "Allow Salt Minion communication" `
            -ErrorAction SilentlyContinue | Out-Null

        Write-Log "Firewall rules configured for: $saltExe"
    } else {
        Write-Log "Could not find salt-minion.exe - skipping firewall configuration" "WARN"
    }
}

function Start-SaltMinionService {
    Write-Log "Configuring Salt Minion service..."

    $serviceName = "salt-minion"
    $maxAttempts = 5
    $attempt = 0

    # Wait for service to be registered
    while ($attempt -lt $maxAttempts) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            break
        }
        $attempt++
        Write-Log "Waiting for service registration... (attempt $attempt/$maxAttempts)" "DEBUG"
        Start-Sleep -Seconds 2
    }

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Service '$serviceName' not found after installation" "ERROR"
        return $false
    }

    # On Domain Controllers, use delayed auto-start so salt-minion waits for
    # AD DS (NTDS) to fully initialize after reboot. Without this, Salt's
    # win32net.NetUserGetLocalGroups() call can fail with error 1355 if AD
    # services haven't started yet.
    if ($isDC) {
        Write-Log "Setting delayed auto-start for DC compatibility"
        sc.exe config $serviceName start= delayed-auto | Out-Null
    } else {
        Set-Service -Name $serviceName -StartupType Automatic
    }

    # Start if not running
    if ($service.Status -ne 'Running') {
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 3
    }

    # Check for "Paused" state - a known issue where Salt's SSM service
    # manager fails to fully start (common with VC++ runtime issues or
    # on DCs where AD queries fail during startup)
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq 'Paused') {
        Write-Log "Service entered 'Paused' state, attempting recovery..." "WARN"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 5
        $service = Get-Service -Name $serviceName
    }

    # Verify running
    if ($service.Status -eq 'Running') {
        Write-Log "Service '$serviceName' is running"
        return $true
    } else {
        Write-Log "Service '$serviceName' status: $($service.Status)" "WARN"
        if ($isDC -and $service.Status -ne 'Running') {
            Write-Log "On DCs, the service may need AD to fully start. Try: Restart-Service salt-minion" "WARN"
        }
        return $false
    }
}

# --- Main Script ---

# Banner
Write-Host ""
Write-Host "#####################################################" -ForegroundColor Green
Write-Host "# Salt Minion Installer for Salt-GUI (Windows)      #" -ForegroundColor Green
Write-Host "# Salt Version: $SaltVersion                              #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host ""

# Administrator check
if (-not (Test-Administrator)) {
    Write-Log "This script must be run with Administrator privileges" "ERROR"
    Write-Log "Please right-click and select 'Run as Administrator'" "WARN"
    if (-not $NonInteractive) {
        Read-Host "Press Enter to exit..."
    }
    exit 1
}

# Get Master IP
if ([string]::IsNullOrWhiteSpace($MasterIP)) {
    $MasterIP = Get-UserInput -Prompt "Enter Salt Master IP" -Default $DEFAULT_MASTER_IP
}
Write-Log "Master IP: $MasterIP"

# Get Minion ID
if ([string]::IsNullOrWhiteSpace($MinionID)) {
    $defaultID = $env:COMPUTERNAME
    $MinionID = Get-UserInput -Prompt "Enter Minion ID" -Default $defaultID
}
Write-Log "Minion ID: $MinionID"

# Detect Domain Controller
$isDC = Test-DomainController
if ($isDC) {
    $dcDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-Log "Domain Controller detected (domain: $dcDomain)" "WARN"
    Write-Log "DC-specific mitigations will be applied" "WARN"
}

# Warn on hostname vs minion ID mismatch
if ($MinionID -ne $env:COMPUTERNAME -and $MinionID -ne $env:COMPUTERNAME.ToLower()) {
    Write-Log "Minion ID '$MinionID' differs from hostname '$($env:COMPUTERNAME)'" "WARN"
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    if ($MinionID -ne $fqdn -and $MinionID -ne $fqdn.ToLower()) {
        Write-Log "Minion ID also differs from FQDN '$fqdn'" "WARN"
    }
}

# Pre-flight checks for common AD/GPO blockers
$preFlightOk = Test-PreFlightChecks -MasterIP $MasterIP
if (-not $preFlightOk) {
    if (-not $NonInteractive) {
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne 'y' -and $continue -ne 'Y') {
            Write-Log "Installation aborted by user"
            exit 1
        }
    } else {
        Write-Log "Pre-flight failures in non-interactive mode, aborting" "ERROR"
        exit 1
    }
}

# Check for existing installation
if (Test-SaltMinionInstalled) {
    Write-Log "Existing Salt Minion installation detected" "WARN"
    Uninstall-ExistingMinion
}

# Get installer URL
$installer = Get-SaltInstallerUrl -Version $SaltVersion
$downloadPath = Join-Path $env:TEMP $installer.FileName
$logPath = Join-Path $env:TEMP "salt_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try {
    # Download installer
    Write-Log "Downloading Salt Minion installer..."
    Write-Log "  URL: $($installer.Url)" "DEBUG"
    Write-Log "  Destination: $downloadPath" "DEBUG"

    # Configure TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Download with retry
    $maxRetries = 3
    $retryCount = 0
    $downloaded = $false

    while (-not $downloaded -and $retryCount -lt $maxRetries) {
        try {
            $retryCount++
            Write-Log "Download attempt $retryCount/$maxRetries..."
            Invoke-WebRequest -Uri $installer.Url -OutFile $downloadPath -UseBasicParsing
            $downloaded = $true
        } catch {
            if ($retryCount -lt $maxRetries) {
                Write-Log "Download failed, retrying in 5 seconds..." "WARN"
                Start-Sleep -Seconds 5
            } else {
                throw
            }
        }
    }

    # Verify download
    if (-not (Test-Path $downloadPath)) {
        throw "Installer file not found after download"
    }

    $fileSize = (Get-Item $downloadPath).Length / 1MB
    Write-Log "Downloaded: $([math]::Round($fileSize, 2)) MB"

    # Install
    Install-SaltMinion -InstallerPath $downloadPath -MasterIP $MasterIP -MinionID $MinionID -LogPath $logPath

    # Configure firewall
    Set-FirewallRules

    # Start service
    $serviceStarted = Start-SaltMinionService

    # Summary
    Write-Host ""
    Write-Host "#####################################################" -ForegroundColor Green
    Write-Host "# MINION SETUP COMPLETE                             #" -ForegroundColor Green
    Write-Host "#####################################################" -ForegroundColor Green
    Write-Host ""
    Write-Host "Minion ID:  $MinionID"
    Write-Host "Master IP:  $MasterIP"
    Write-Host "Status:     $(if ($serviceStarted) { 'Running' } else { 'Check Required' })"
    if ($isDC) {
        Write-Host "DC Mode:    Yes (delayed auto-start enabled)"
    }
    Write-Host "Log File:   $logPath"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Accept the key on the master:"
    Write-Host "     salt-key -a '$MinionID'"
    Write-Host "  2. Test connectivity:"
    Write-Host "     salt '$MinionID' test.ping"
    Write-Host ""

} catch {
    Write-Log "An error occurred: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    if (-not $NonInteractive) {
        Read-Host "Press Enter to exit..."
    }
    exit 1
} finally {
    # Cleanup downloaded installer
    if (Test-Path $downloadPath) {
        Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue
    }
}

if (-not $NonInteractive) {
    Read-Host "Press Enter to exit..."
}
