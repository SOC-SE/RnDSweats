<#
.SYNOPSIS
    Cross-Platform Reboot Script
    Runs on Windows and Linux (requires PowerShell installed).
#>

Write-Host "[*] Initiating System Reboot Sequence..." -ForegroundColor Cyan

# 1. Check for Administrator/Root privileges
$isWindows = $IsWindows -or ($PSVersionTable.Platform -eq "Win32NT") -or ($PSVersionTable.PSEdition -eq "Desktop")
$isLinux = $IsLinux -or ($PSVersionTable.Platform -eq "Unix")

if ($isWindows) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Warning "You are not running as Administrator. Reboot might fail."
    }
}
elseif ($isLinux) {
    if ($env:USER -ne "root") {
        Write-Warning "You are not running as root. Reboot might fail."
    }
}

# 2. Attempt Reboot
try {
    Write-Host "    Attempting standard PowerShell reboot..."
    # -Force is crucial for Windows to ignore open apps
    Restart-Computer -Force -ErrorAction Stop
}
catch {
    Write-Warning "    'Restart-Computer' cmdlet failed. Attempting native OS fallback..."
    
    if ($isWindows) {
        # Windows Native Fallback
        & shutdown.exe /r /t 0 /f
    }
    elseif ($isLinux) {
        # Linux Native Fallback
        # Try systemctl first (modern), then shutdown (legacy/universal)
        try {
            & systemctl reboot
        }
        catch {
            & shutdown -r now
        }
    }
    else {
        Write-Error "    Could not determine OS for fallback command."
    }
}