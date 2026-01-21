# ==============================================================================
# User Audit - Windows
# Comprehensive user account security check
# ==============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "USER AUDIT - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] ALL LOCAL USERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon | Format-Table -AutoSize

Write-Host "`n[2/12] LOCAL ADMINISTRATORS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
    Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize

Write-Host "`n[3/12] REMOTE DESKTOP USERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | 
    Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize

Write-Host "`n[4/12] USERS WITH NO PASSWORD REQUIRED" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false -and $_.Enabled -eq $true} | 
    Select-Object Name, Enabled, PasswordRequired | Format-Table -AutoSize

Write-Host "`n[5/12] USERS THAT NEVER EXPIRE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalUser | Where-Object {$_.PasswordExpires -eq $null -and $_.Enabled -eq $true} |
    Select-Object Name, PasswordExpires | Format-Table -AutoSize

Write-Host "`n[6/12] DISABLED ACCOUNTS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalUser | Where-Object {$_.Enabled -eq $false} | Select-Object Name | Format-Table -AutoSize

Write-Host "`n[7/12] RECENTLY CREATED ACCOUNTS (7 days)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject -Class Win32_UserAccount | Where-Object {
    $_.LocalAccount -eq $true
} | ForEach-Object {
    $created = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720} -ErrorAction SilentlyContinue | 
        Where-Object {$_.Properties[0].Value -eq $_.Name} | Select-Object -First 1
    if ($created -and $created.TimeCreated -gt (Get-Date).AddDays(-7)) {
        [PSCustomObject]@{
            Name = $_.Name
            Created = $created.TimeCreated
        }
    }
}

Write-Host "`n[8/12] RECENT SUCCESSFUL LOGONS (Last 20)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue | 
    Where-Object {$_.Properties[8].Value -ne 3} |  # Exclude Network logons
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}} |
    Select-Object -First 20 | Format-Table -AutoSize

Write-Host "`n[9/12] RECENT FAILED LOGONS (Last 20)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[19].Value}} |
    Format-Table -AutoSize

Write-Host "`n[10/12] LOGGED ON SESSIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
query user 2>$null

Write-Host "`n[11/12] CACHED LOGON CREDENTIALS COUNT" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$cachedLogons = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
Write-Host "Cached logons allowed: $cachedLogons"

Write-Host "`n[12/12] ALL LOCAL GROUPS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalGroup | Select-Object Name, Description | Format-Table -AutoSize

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "USER AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
