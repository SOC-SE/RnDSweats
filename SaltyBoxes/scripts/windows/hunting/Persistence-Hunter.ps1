# ==============================================================================
# Persistence Hunter - Windows
# Comprehensive check for attacker persistence mechanisms
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

#Requires -Version 5.1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PERSISTENCE HUNTER - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/15] SCHEDULED TASKS (Non-Microsoft)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {$_.Author -notlike "*Microsoft*" -and $_.State -ne "Disabled"}
    if ($tasks) {
        $tasks | Select-Object TaskName, TaskPath, State, Author | Format-Table -AutoSize
    } else {
        Write-Host "No non-Microsoft scheduled tasks found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to retrieve scheduled tasks" -ForegroundColor Red
}

Write-Host "`n[2/15] RUN KEYS (HKLM)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
} catch {
    Write-Host "Unable to read registry" -ForegroundColor Red
}

Write-Host "`n[3/15] RUN KEYS (HKCU)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
} catch {
    Write-Host "Unable to read registry" -ForegroundColor Red
}

Write-Host "`n[4/15] STARTUP FOLDER ITEMS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $startupPaths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Write-Host "=== $path ===" -ForegroundColor Cyan
            Get-ChildItem $path -ErrorAction SilentlyContinue | Select-Object Name, FullName
        }
    }
} catch {
    Write-Host "Unable to read startup folders" -ForegroundColor Red
}

Write-Host "`n[5/15] SERVICES (Non-Microsoft, Running)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.State -eq "Running" -and
        $_.PathName -notlike "*System32*" -and
        $_.PathName -notlike "*SysWOW64*"
    } | Select-Object Name, DisplayName, PathName, StartMode | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve services" -ForegroundColor Red
}

Write-Host "`n[6/15] SUSPICIOUS SERVICES (Temp paths)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $suspicious = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -like "*temp*" -or
        $_.PathName -like "*tmp*" -or
        $_.PathName -like "*appdata*" -or
        ($_.PathName -like "*programdata*" -and $_.PathName -notlike "*Microsoft*")
    }
    if ($suspicious) {
        $suspicious | Select-Object Name, PathName, State | Format-Table -AutoSize
    } else {
        Write-Host "None found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check" -ForegroundColor Red
}

Write-Host "`n[7/15] WMI SUBSCRIPTIONS (Persistence)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

    if ($consumers) { $consumers | Select-Object Name, __CLASS | Format-Table -AutoSize }
    if ($filters) { $filters | Select-Object Name, Query | Format-Table -AutoSize }
    if ($bindings) { $bindings | Select-Object Filter, Consumer | Format-Table -AutoSize }
    if (-not $consumers -and -not $filters -and -not $bindings) {
        Write-Host "No WMI subscriptions found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check WMI subscriptions" -ForegroundColor Red
}

Write-Host "`n[8/15] BITS JOBS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $bits = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    if ($bits) {
        $bits | Select-Object DisplayName, JobState, TransferType | Format-Table -AutoSize
    } else {
        Write-Host "No BITS jobs" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check BITS jobs" -ForegroundColor Yellow
}

Write-Host "`n[9/15] UNSIGNED DRIVERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {$_.Started -eq $true} | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne "Valid") {
            [PSCustomObject]@{
                Name = $_.Name
                Path = $_.PathName
                SignatureStatus = $sig.Status
            }
        }
    } | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check driver signatures" -ForegroundColor Yellow
}

Write-Host "`n[10/15] COM HIJACKING LOCATIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $suspiciousCOM = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
        $default = (Get-ItemProperty "$($_.PSPath)\InProcServer32" -ErrorAction SilentlyContinue).'(default)'
        if ($default -and $default -notlike "*System32*" -and $default -notlike "*SysWOW64*") {
            [PSCustomObject]@{
                CLSID = $_.PSChildName
                Path = $default
            }
        }
    }
    if ($suspiciousCOM) {
        $suspiciousCOM | Format-Table -AutoSize
    } else {
        Write-Host "No suspicious COM hijacks found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check COM hijacking" -ForegroundColor Yellow
}

Write-Host "`n[11/15] POWERSHELL PROFILES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$profiles = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)
foreach ($p in $profiles) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        Write-Host "EXISTS: $p" -ForegroundColor Red
        Get-Content $p -ErrorAction SilentlyContinue | Select-Object -First 10
    }
}

Write-Host "`n[12/15] BROWSER EXTENSIONS (Chrome)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -ErrorAction SilentlyContinue |
        Select-Object Name, LastWriteTime | Format-Table -AutoSize
} catch {
    Write-Host "Chrome extensions not found or not accessible" -ForegroundColor Yellow
}

Write-Host "`n[13/15] NETSH HELPER DLLS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NetSh" -ErrorAction SilentlyContinue | Format-List
} catch {
    Write-Host "Unable to check" -ForegroundColor Yellow
}

Write-Host "`n[14/15] IMAGE FILE EXECUTION OPTIONS (Debuggers)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object {
        $debugger = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Write-Host "$($_.PSChildName): $debugger" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Unable to check IFEO" -ForegroundColor Yellow
}

Write-Host "`n[15/15] RECENTLY MODIFIED EXECUTABLES IN SYSTEM FOLDERS (7 days)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $sevenDaysAgo = (Get-Date).AddDays(-7)
    Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue |
        Where-Object {$_.LastWriteTime -gt $sevenDaysAgo} |
        Select-Object Name, LastWriteTime | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PERSISTENCE HUNT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
