# ==============================================================================
# Process Hunter - Windows
# Find suspicious processes and potential malware
# ==============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PROCESS HUNTER - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/12] HIGH CPU PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name, Id, CPU, @{N='Memory(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}} | Format-Table -AutoSize

Write-Host "`n[2/12] HIGH MEMORY PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 Name, Id, @{N='Memory(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}}, CPU | Format-Table -AutoSize

Write-Host "`n[3/12] PROCESSES WITH NETWORK CONNECTIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetTCPConnection -State Established,Listen | Select-Object -Unique OwningProcess | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($proc) {
        [PSCustomObject]@{
            PID = $proc.Id
            Name = $proc.ProcessName
            Path = $proc.Path
        }
    }
} | Format-Table -AutoSize

Write-Host "`n[4/12] PROCESSES FROM TEMP DIRECTORIES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Where-Object {
    $_.Path -like "*\Temp\*" -or 
    $_.Path -like "*\tmp\*" -or
    $_.Path -like "*\AppData\Local\Temp\*"
} | Select-Object Name, Id, Path | Format-Table -AutoSize

Write-Host "`n[5/12] UNSIGNED PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid") {
        [PSCustomObject]@{
            Name = $_.ProcessName
            PID = $_.Id
            Path = $_.Path
            SigStatus = $sig.Status
        }
    }
} | Select-Object -First 20 | Format-Table -AutoSize

Write-Host "`n[6/12] PROCESSES WITH SUSPICIOUS NAMES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$suspiciousPatterns = @('mimikatz', 'lazagne', 'psexec', 'procdump', 'pwdump', 'wce', 'gsecdump', 'nc', 'ncat', 'netcat', 'powercat', 'empire', 'beacon', 'meterpreter', 'shell', 'rat', 'cryptominer', 'xmrig')
Get-Process | Where-Object {
    $name = $_.ProcessName.ToLower()
    $suspiciousPatterns | Where-Object { $name -like "*$_*" }
} | Select-Object Name, Id, Path | Format-Table -AutoSize

if (-not $?) { Write-Host "None found" -ForegroundColor Green }

Write-Host "`n[7/12] POWERSHELL PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Where-Object {$_.ProcessName -like "*powershell*" -or $_.ProcessName -like "*pwsh*"} | 
    Select-Object Name, Id, @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} |
    Format-Table -AutoSize -Wrap

Write-Host "`n[8/12] CMD PROCESSES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Where-Object {$_.ProcessName -eq "cmd"} | 
    Select-Object Name, Id, @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} |
    Format-Table -AutoSize -Wrap

Write-Host "`n[9/12] PROCESSES WITH NO WINDOW" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Where-Object {$_.MainWindowHandle -eq 0 -and $_.Path} | 
    Select-Object Name, Id, Path | Select-Object -First 30 | Format-Table -AutoSize

Write-Host "`n[10/12] RECENTLY STARTED PROCESSES (Last 5 min)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$5MinAgo = (Get-Date).AddMinutes(-5)
Get-CimInstance Win32_Process | Where-Object {$_.CreationDate -gt $5MinAgo} |
    Select-Object ProcessId, Name, CreationDate, @{N='User';E={$_.GetOwner().User}} |
    Format-Table -AutoSize

Write-Host "`n[11/12] PROCESSES BY USER" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-CimInstance Win32_Process | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        PID = $_.ProcessId
        User = $_.GetOwner().User
    }
} | Group-Object User | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host "`n[12/12] PARENT-CHILD RELATIONSHIPS (Suspicious)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
# Look for cmd/powershell spawned from unusual parents
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "cmd|powershell|pwsh"
} | ForEach-Object {
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ChildPID = $_.ProcessId
        ChildName = $_.Name
        ParentPID = $_.ParentProcessId
        ParentName = $parent.Name
    }
} | Format-Table -AutoSize

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PROCESS HUNT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
