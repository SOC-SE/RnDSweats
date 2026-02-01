<#
Hunt for common persistence mechanisms on Windows
#>

Write-Host "=== Windows Persistence Hunt ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "=== Scheduled Tasks (Non-Microsoft) ===" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.Author -notlike "*Microsoft*" -and $_.State -ne 'Disabled' } |
    Select-Object TaskName, Author, State | Format-Table -AutoSize
Write-Host ""

Write-Host "=== Run Keys (Current User) ===" -ForegroundColor Yellow
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Select-Object -Property * -ExcludeProperty PS*
Write-Host ""

Write-Host "=== Run Keys (Local Machine) ===" -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Select-Object -Property * -ExcludeProperty PS*
Write-Host ""

Write-Host "=== Services with Suspicious Paths ===" -ForegroundColor Yellow
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and (
        $_.PathName -like "*temp*" -or
        $_.PathName -like "*appdata*" -or
        $_.PathName -like "*programdata*"
    )
} | Select-Object Name, PathName, StartMode, State | Format-Table -AutoSize
Write-Host ""

Write-Host "=== Startup Folder Items ===" -ForegroundColor Yellow
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object Name, FullName
    }
}
Write-Host ""

Write-Host "=== WMI Event Subscriptions ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
    Select-Object Name, @{N='Class';E={$_.CimClass.CimClassName}}
Write-Host ""

Write-Host "=== Hunt Complete ===" -ForegroundColor Cyan
