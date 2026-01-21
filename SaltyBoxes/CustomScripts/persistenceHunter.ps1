# ==============================================================================
# Persistence Hunter - Windows
# Comprehensive check for attacker persistence mechanisms
# For CCDC Competition Use
# ==============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PERSISTENCE HUNTER - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/15] SCHEDULED TASKS (Non-Microsoft)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ScheduledTask | Where-Object {$_.Author -notlike "*Microsoft*" -and $_.State -ne "Disabled"} | 
    Select-Object TaskName, TaskPath, State, Author | Format-Table -AutoSize

Write-Host "`n[2/15] RUN KEYS (HKLM)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>$null | Format-List
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>$null | Format-List

Write-Host "`n[3/15] RUN KEYS (HKCU)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>$null | Format-List
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>$null | Format-List

Write-Host "`n[4/15] STARTUP FOLDER ITEMS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" 2>$null | Select-Object Name, FullName
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" 2>$null | Select-Object Name, FullName

Write-Host "`n[5/15] SERVICES (Non-Microsoft, Running)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject Win32_Service | Where-Object {
    $_.State -eq "Running" -and 
    $_.PathName -notlike "*System32*" -and 
    $_.PathName -notlike "*SysWOW64*"
} | Select-Object Name, DisplayName, PathName, StartMode | Format-Table -AutoSize

Write-Host "`n[6/15] SUSPICIOUS SERVICES (New/Unknown)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -like "*temp*" -or 
    $_.PathName -like "*tmp*" -or
    $_.PathName -like "*appdata*" -or
    $_.PathName -like "*programdata*" -and $_.PathName -notlike "*Microsoft*"
} | Select-Object Name, PathName, State | Format-Table -AutoSize

Write-Host "`n[7/15] WMI SUBSCRIPTIONS (Persistence)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject -Namespace root\subscription -Class __EventConsumer 2>$null | Select-Object Name, __CLASS
Get-WmiObject -Namespace root\subscription -Class __EventFilter 2>$null | Select-Object Name, Query
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding 2>$null | Select-Object Filter, Consumer

Write-Host "`n[8/15] BITS JOBS (Can be used for persistence)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-BitsTransfer -AllUsers 2>$null | Select-Object DisplayName, JobState, TransferType | Format-Table -AutoSize

Write-Host "`n[9/15] UNSIGNED DRIVERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject Win32_SystemDriver | Where-Object {$_.Started -eq $true} | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.PathName 2>$null
    if ($sig.Status -ne "Valid") {
        [PSCustomObject]@{
            Name = $_.Name
            Path = $_.PathName
            SignatureStatus = $sig.Status
        }
    }
} | Format-Table -AutoSize

Write-Host "`n[10/15] COM HIJACKING LOCATIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$suspiciousCOM = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" 2>$null | ForEach-Object {
    $default = (Get-ItemProperty "$($_.PSPath)\InProcServer32" 2>$null).'(default)'
    if ($default -and $default -notlike "*System32*" -and $default -notlike "*SysWOW64*") {
        [PSCustomObject]@{
            CLSID = $_.PSChildName
            Path = $default
        }
    }
}
$suspiciousCOM | Format-Table -AutoSize

Write-Host "`n[11/15] POWERSHELL PROFILES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$profiles = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)
foreach ($p in $profiles) {
    if (Test-Path $p) {
        Write-Host "EXISTS: $p" -ForegroundColor Red
        Get-Content $p | Select-Object -First 10
    }
}

Write-Host "`n[12/15] BROWSER EXTENSIONS (Chrome)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" 2>$null | 
    Select-Object Name, LastWriteTime | Format-Table -AutoSize

Write-Host "`n[13/15] NETSH HELPER DLLS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NetSh" 2>$null | Format-List

Write-Host "`n[14/15] IMAGE FILE EXECUTION OPTIONS (Debuggers)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" 2>$null | ForEach-Object {
    $debugger = (Get-ItemProperty $_.PSPath).Debugger
    if ($debugger) {
        Write-Host "$($_.PSChildName): $debugger" -ForegroundColor Red
    }
}

Write-Host "`n[15/15] RECENTLY MODIFIED EXECUTABLES IN SYSTEM FOLDERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ChildItem "C:\Windows\System32\*.exe" | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
    Select-Object Name, LastWriteTime | Format-Table -AutoSize

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PERSISTENCE HUNT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
