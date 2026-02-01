# ==============================================================================
# Process Hunter - Windows
# Find suspicious processes and potential malware
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

#Requires -Version 5.1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PROCESS HUNTER - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] HIGH CPU PROCESSES (Top 15)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-Process -ErrorAction SilentlyContinue | Sort-Object CPU -Descending |
        Select-Object -First 15 Name, Id, CPU, @{N='Memory(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}} |
        Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve processes" -ForegroundColor Red
}

Write-Host "`n[2/12] HIGH MEMORY PROCESSES (Top 15)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending |
        Select-Object -First 15 Name, Id, @{N='Memory(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}}, CPU |
        Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve processes" -ForegroundColor Red
}

Write-Host "`n[3/12] PROCESSES WITH NETWORK CONNECTIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue |
        Select-Object -Unique OwningProcess | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                [PSCustomObject]@{
                    PID = $proc.Id
                    Name = $proc.ProcessName
                    Path = $proc.Path
                }
            }
        } | Format-Table -AutoSize
} catch {
    Write-Host "Unable to retrieve network processes" -ForegroundColor Red
}

Write-Host "`n[4/12] PROCESSES FROM TEMP DIRECTORIES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $tempProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*\Temp\*" -or
        $_.Path -like "*\tmp\*" -or
        $_.Path -like "*\AppData\Local\Temp\*"
    }
    if ($tempProcs) {
        $tempProcs | Select-Object Name, Id, Path | Format-Table -AutoSize
    } else {
        Write-Host "None found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check" -ForegroundColor Red
}

Write-Host "`n[5/12] UNSIGNED PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Path} | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne "Valid") {
            [PSCustomObject]@{
                Name = $_.ProcessName
                PID = $_.Id
                Path = $_.Path
                SigStatus = $sig.Status
            }
        }
    } | Select-Object -First 20 | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check signatures" -ForegroundColor Yellow
}

Write-Host "`n[6/12] PROCESSES WITH SUSPICIOUS NAMES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$suspiciousPatterns = @('mimikatz', 'lazagne', 'psexec', 'procdump', 'pwdump', 'wce', 'gsecdump',
                        'nc', 'ncat', 'netcat', 'powercat', 'empire', 'beacon', 'meterpreter',
                        'shell', 'rat', 'cryptominer', 'xmrig', 'rubeus', 'kerberoast')
try {
    $suspicious = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $name = $_.ProcessName.ToLower()
        $suspiciousPatterns | Where-Object { $name -like "*$_*" }
    }
    if ($suspicious) {
        $suspicious | Select-Object Name, Id, Path | Format-Table -AutoSize
    } else {
        Write-Host "None found" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check" -ForegroundColor Red
}

Write-Host "`n[7/12] POWERSHELL PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object {$_.ProcessName -like "*powershell*" -or $_.ProcessName -like "*pwsh*"} |
        ForEach-Object {
            $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
            [PSCustomObject]@{
                Name = $_.ProcessName
                Id = $_.Id
                CommandLine = $cmdline
            }
        } | Format-Table -AutoSize -Wrap
} catch {
    Write-Host "Unable to retrieve PowerShell processes" -ForegroundColor Yellow
}

Write-Host "`n[8/12] CMD PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -eq "cmd"} |
        ForEach-Object {
            $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
            [PSCustomObject]@{
                Name = $_.ProcessName
                Id = $_.Id
                CommandLine = $cmdline
            }
        } | Format-Table -AutoSize -Wrap
} catch {
    Write-Host "Unable to retrieve CMD processes" -ForegroundColor Yellow
}

Write-Host "`n[9/12] PROCESSES WITH NO WINDOW" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object {$_.MainWindowHandle -eq 0 -and $_.Path} |
        Select-Object -First 30 Name, Id, Path | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check" -ForegroundColor Yellow
}

Write-Host "`n[10/12] RECENTLY STARTED PROCESSES (Last 5 min)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $5MinAgo = (Get-Date).AddMinutes(-5)
    $recent = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {$_.CreationDate -gt $5MinAgo}
    if ($recent) {
        $recent | Select-Object ProcessId, Name, CreationDate, @{N='User';E={$_.GetOwner().User}} | Format-Table -AutoSize
    } else {
        Write-Host "No processes started in last 5 minutes" -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to check" -ForegroundColor Yellow
}

Write-Host "`n[11/12] PROCESSES BY USER" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            PID = $_.ProcessId
            User = $_.GetOwner().User
        }
    } | Group-Object User | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
} catch {
    Write-Host "Unable to group by user" -ForegroundColor Yellow
}

Write-Host "`n[12/12] PARENT-CHILD RELATIONSHIPS (cmd/powershell)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {$_.Name -match "cmd|powershell|pwsh"} |
        ForEach-Object {
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                ChildPID = $_.ProcessId
                ChildName = $_.Name
                ParentPID = $_.ParentProcessId
                ParentName = $parent.Name
            }
        } | Format-Table -AutoSize
} catch {
    Write-Host "Unable to check parent-child relationships" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PROCESS HUNT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
