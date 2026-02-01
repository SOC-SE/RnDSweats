<#
Disable commonly exploited Windows services
#>

$services = @(
    "RemoteRegistry",       # Remote registry access
    "Fax",                  # Fax service
    "XblAuthManager",       # Xbox Live
    "XblGameSave",          # Xbox Live
    "WSearch",              # Windows Search (can be CPU intensive)
    "DiagTrack",            # Telemetry
    "dmwappushservice"      # WAP Push Service
)

Write-Host "=== Disabling Common Services ===" -ForegroundColor Cyan

foreach ($svc in $services) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        try {
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc -Force -ErrorAction Stop
                Write-Host "Stopped: $svc" -ForegroundColor Green
            }
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Write-Host "Disabled: $svc" -ForegroundColor Green
        } catch {
            Write-Host "Failed: $svc - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Not found: $svc" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Service Hardening Complete ===" -ForegroundColor Cyan
