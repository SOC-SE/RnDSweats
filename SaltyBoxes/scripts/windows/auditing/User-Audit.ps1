# ==============================================================================
# User Audit - Windows
# Comprehensive user account security check
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

#Requires -Version 5.1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "USER AUDIT - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] ALL LOCAL USERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve local users (may need admin rights)" -ForegroundColor Red
}

Write-Host "`n[2/12] LOCAL ADMINISTRATORS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve administrators" -ForegroundColor Red
}

Write-Host "`n[3/12] REMOTE DESKTOP USERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue |
        Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize
} catch {
    Write-Host "Group not found or no members" -ForegroundColor Yellow
}

Write-Host "`n[4/12] USERS WITH NO PASSWORD REQUIRED" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $noPass = Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object {$_.PasswordRequired -eq $false -and $_.Enabled -eq $true}
    if ($noPass) {
        $noPass | Select-Object Name, Enabled, PasswordRequired | Format-Table -AutoSize
    } else {
        Write-Host "None found (good)" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check" -ForegroundColor Red
}

Write-Host "`n[5/12] USERS THAT NEVER EXPIRE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object {$_.PasswordExpires -eq $null -and $_.Enabled -eq $true} |
        Select-Object Name, PasswordExpires | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check" -ForegroundColor Red
}

Write-Host "`n[6/12] DISABLED ACCOUNTS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object {$_.Enabled -eq $false} |
        Select-Object Name | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check" -ForegroundColor Red
}

Write-Host "`n[7/12] RECENTLY CREATED ACCOUNTS (7 days)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $sevenDaysAgo = (Get-Date).AddDays(-7)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720} -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object {$_.TimeCreated -gt $sevenDaysAgo}
    if ($events) {
        $events | Select-Object TimeCreated, @{N='User';E={$_.Properties[0].Value}} | Format-Table -AutoSize
    } else {
        Write-Host "No accounts created in last 7 days" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check (may need admin rights)" -ForegroundColor Yellow
}

Write-Host "`n[8/12] RECENT SUCCESSFUL LOGONS (Last 20)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object {$_.Properties[8].Value -ne 3} |
        Select-Object -First 20 TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}} |
        Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve (may need admin rights)" -ForegroundColor Yellow
}

Write-Host "`n[9/12] RECENT FAILED LOGONS (Last 20)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $failed = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($failed) {
        $failed | Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[19].Value}} |
            Format-Table -AutoSize
    } else {
        Write-Host "No recent failed logons" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to retrieve (may need admin rights)" -ForegroundColor Yellow
}

Write-Host "`n[10/12] LOGGED ON SESSIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $sessions = query user 2>$null
    if ($sessions) {
        $sessions
    } else {
        Write-Host "No active sessions or command not available"
    }
} catch {
    Write-Host "Unable to query sessions"
}

Write-Host "`n[11/12] CACHED LOGON CREDENTIALS COUNT" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $cachedLogons = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
    Write-Host "Cached logons allowed: $cachedLogons"
} catch {
    Write-Host "Unable to retrieve cached logon count" -ForegroundColor Yellow
}

Write-Host "`n[12/12] ALL LOCAL GROUPS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-LocalGroup -ErrorAction SilentlyContinue |
        Select-Object Name, Description | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve groups" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "USER AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
