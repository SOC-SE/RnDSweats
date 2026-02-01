<#
Gather basic system information for Windows inventory
#>

Write-Host "=== System Information ===" -ForegroundColor Cyan
Write-Host "Hostname: $env:COMPUTERNAME"
Write-Host "Domain: $env:USERDOMAIN"
Write-Host "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Host "Version: $((Get-CimInstance Win32_OperatingSystem).Version)"
Write-Host ""

Write-Host "=== Network Configuration ===" -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } |
    Select-Object InterfaceAlias, IPAddress | Format-Table -AutoSize
Write-Host ""

Write-Host "=== Local Users ===" -ForegroundColor Cyan
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize
Write-Host ""

Write-Host "=== Local Administrators ===" -ForegroundColor Cyan
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Format-Table -AutoSize
Write-Host ""

Write-Host "=== Listening Ports ===" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort | Format-Table -AutoSize
