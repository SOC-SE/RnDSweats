# ==============================================================================
# File Integrity Baseline - Windows
# Create SHA256 hashes of critical system files for later comparison
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

#Requires -Version 5.1

param(
    [string]$BaselineDir = "C:\Baselines"
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaselineFile = Join-Path $BaselineDir "baseline_$env:COMPUTERNAME`_$Timestamp.csv"
$SummaryFile = Join-Path $BaselineDir "baseline_$env:COMPUTERNAME`_$Timestamp.summary.txt"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FILE INTEGRITY BASELINE - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Output: $BaselineFile" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create baseline directory
New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null

$results = @()
$totalFiles = 0
$failedFiles = 0

function Get-FileHashSafe {
    param([string]$Path, [string]$Category)

    if (Test-Path $Path -PathType Leaf) {
        try {
            $hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
            $script:totalFiles++
            return [PSCustomObject]@{
                Category = $Category
                Path = $Path
                Hash = $hash
                LastWriteTime = (Get-Item $Path).LastWriteTime
            }
        } catch {
            $script:failedFiles++
            return $null
        }
    }
    return $null
}

function Get-DirectoryHashesSafe {
    param([string]$Path, [string]$Category, [string]$Filter = "*")

    if (Test-Path $Path -PathType Container) {
        Get-ChildItem -Path $Path -Filter $Filter -File -ErrorAction SilentlyContinue | ForEach-Object {
            Get-FileHashSafe -Path $_.FullName -Category $Category
        }
    }
}

Write-Host "`n[1/8] CRITICAL SYSTEM BINARIES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$criticalBins = @(
    "C:\Windows\System32\cmd.exe",
    "C:\Windows\System32\powershell.exe",
    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "C:\Windows\System32\net.exe",
    "C:\Windows\System32\net1.exe",
    "C:\Windows\System32\netsh.exe",
    "C:\Windows\System32\schtasks.exe",
    "C:\Windows\System32\reg.exe",
    "C:\Windows\System32\wmic.exe",
    "C:\Windows\System32\tasklist.exe",
    "C:\Windows\System32\taskkill.exe",
    "C:\Windows\System32\sc.exe",
    "C:\Windows\System32\whoami.exe",
    "C:\Windows\System32\ipconfig.exe",
    "C:\Windows\System32\netstat.exe",
    "C:\Windows\System32\lsass.exe",
    "C:\Windows\System32\services.exe",
    "C:\Windows\System32\svchost.exe",
    "C:\Windows\System32\csrss.exe",
    "C:\Windows\System32\winlogon.exe"
)

foreach ($bin in $criticalBins) {
    $result = Get-FileHashSafe -Path $bin -Category "CriticalBinary"
    if ($result) {
        $results += $result
        Write-Host "  Hashed: $bin"
    }
}

Write-Host "`n[2/8] SYSTEM DLLs" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$criticalDlls = @(
    "C:\Windows\System32\ntdll.dll",
    "C:\Windows\System32\kernel32.dll",
    "C:\Windows\System32\advapi32.dll",
    "C:\Windows\System32\user32.dll",
    "C:\Windows\System32\ws2_32.dll",
    "C:\Windows\System32\crypt32.dll",
    "C:\Windows\System32\secur32.dll",
    "C:\Windows\System32\netapi32.dll"
)

foreach ($dll in $criticalDlls) {
    $result = Get-FileHashSafe -Path $dll -Category "SystemDLL"
    if ($result) {
        $results += $result
        Write-Host "  Hashed: $dll"
    }
}

Write-Host "`n[3/8] AUTHENTICATION FILES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$authFiles = @(
    "C:\Windows\System32\config\SAM",
    "C:\Windows\System32\config\SYSTEM",
    "C:\Windows\System32\config\SECURITY"
)

foreach ($f in $authFiles) {
    # These are locked, but we can still try
    $result = Get-FileHashSafe -Path $f -Category "AuthFile"
    if ($result) {
        $results += $result
        Write-Host "  Hashed: $f"
    } else {
        Write-Host "  Skipped (locked): $f" -ForegroundColor Yellow
    }
}

Write-Host "`n[4/8] HOSTS AND NETWORK CONFIG" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$netFiles = @(
    "C:\Windows\System32\drivers\etc\hosts",
    "C:\Windows\System32\drivers\etc\services",
    "C:\Windows\System32\drivers\etc\protocol"
)

foreach ($f in $netFiles) {
    $result = Get-FileHashSafe -Path $f -Category "NetworkConfig"
    if ($result) {
        $results += $result
        Write-Host "  Hashed: $f"
    }
}

Write-Host "`n[5/8] STARTUP LOCATIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$startupPaths = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $startupPaths) {
    $hashes = Get-DirectoryHashesSafe -Path $path -Category "Startup"
    if ($hashes) {
        $results += $hashes
        Write-Host "  Hashed files in: $path"
    }
}

Write-Host "`n[6/8] WMI PROVIDERS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$wmiPath = "C:\Windows\System32\wbem"
$wmiFiles = Get-ChildItem -Path $wmiPath -Filter "*.dll" -File -ErrorAction SilentlyContinue | Select-Object -First 20
foreach ($file in $wmiFiles) {
    $result = Get-FileHashSafe -Path $file.FullName -Category "WMI"
    if ($result) { $results += $result }
}
Write-Host "  Hashed WMI provider DLLs"

Write-Host "`n[7/8] BOOT FILES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$bootFiles = @(
    "C:\Windows\System32\bootmgr",
    "C:\Windows\System32\winload.exe",
    "C:\Windows\Boot\BCD"
)

foreach ($f in $bootFiles) {
    $result = Get-FileHashSafe -Path $f -Category "Boot"
    if ($result) {
        $results += $result
        Write-Host "  Hashed: $f"
    }
}

Write-Host "`n[8/8] COMMON ATTACK TOOLS LOCATIONS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
# Hash anything in common attack tool locations for detection
$suspiciousPaths = @(
    "C:\Windows\Temp",
    "C:\Users\Public",
    "$env:TEMP"
)

foreach ($path in $suspiciousPaths) {
    $files = Get-ChildItem -Path $path -Filter "*.exe" -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $result = Get-FileHashSafe -Path $file.FullName -Category "SuspiciousLocation"
        if ($result) { $results += $result }
    }
}
Write-Host "  Hashed executables in temp locations"

# Export results
$results | Export-Csv -Path $BaselineFile -NoTypeInformation

# Create summary
$summary = @"
========================================
FILE INTEGRITY BASELINE SUMMARY
========================================
Baseline created: $(Get-Date)
Hostname: $env:COMPUTERNAME
Total files hashed: $totalFiles
Files that couldn't be hashed: $failedFiles
Baseline file: $BaselineFile

To verify later, run:
  `$baseline = Import-Csv '$BaselineFile'
  `$baseline | ForEach-Object {
      `$current = (Get-FileHash -Path `$_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
      if (`$current -ne `$_.Hash) { Write-Host "CHANGED: `$(`$_.Path)" }
  }
========================================
"@

$summary | Out-File -FilePath $SummaryFile
Write-Host $summary

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "FILE INTEGRITY BASELINE COMPLETE" -ForegroundColor Green
Write-Host "Baseline: $BaselineFile" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
