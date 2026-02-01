# ==============================================================================
# Forensic Artifact Collection - Windows
# Collect key artifacts before remediation
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

#Requires -Version 5.1

$ArtifactDir = "C:\Temp\artifacts_$env:COMPUTERNAME_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $ArtifactDir -Force | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ARTIFACT COLLECTION - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Output: $ArtifactDir" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/10] PROCESS LISTING" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-Process | Select-Object Id, ProcessName, Path, Company, StartTime, CPU, WorkingSet64 |
    Export-Csv "$ArtifactDir\processes.csv" -NoTypeInformation
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate |
    Export-Csv "$ArtifactDir\processes_wmi.csv" -NoTypeInformation
Write-Host "Saved process listings"

Write-Host "`n[2/10] NETWORK STATE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Export-Csv "$ArtifactDir\tcp_connections.csv" -NoTypeInformation
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess |
    Export-Csv "$ArtifactDir\udp_endpoints.csv" -NoTypeInformation
Get-NetNeighbor | Export-Csv "$ArtifactDir\arp_table.csv" -NoTypeInformation
Get-DnsClientCache | Export-Csv "$ArtifactDir\dns_cache.csv" -NoTypeInformation
Write-Host "Saved network state"

Write-Host "`n[3/10] USER INFORMATION" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-LocalUser | Export-Csv "$ArtifactDir\local_users.csv" -NoTypeInformation
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{Group=$group; Member=$_.Name; Type=$_.ObjectClass}
    }
} | Export-Csv "$ArtifactDir\group_memberships.csv" -NoTypeInformation
qwinsta 2>$null | Out-File "$ArtifactDir\active_sessions.txt"
Write-Host "Saved user information"

Write-Host "`n[4/10] SCHEDULED TASKS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author |
    Export-Csv "$ArtifactDir\scheduled_tasks.csv" -NoTypeInformation
schtasks /query /fo CSV /v 2>$null | Out-File "$ArtifactDir\scheduled_tasks_detail.csv"
Write-Host "Saved scheduled tasks"

Write-Host "`n[5/10] SERVICES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Export-Csv "$ArtifactDir\services.csv" -NoTypeInformation
Write-Host "Saved service information"

Write-Host "`n[6/10] REGISTRY PERSISTENCE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)
$regData = foreach ($path in $regPaths) {
    try {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                [PSCustomObject]@{Path=$path; Name=$_.Name; Value=$_.Value}
            }
        }
    } catch {}
}
$regData | Export-Csv "$ArtifactDir\registry_persistence.csv" -NoTypeInformation
Write-Host "Saved registry persistence keys"

Write-Host "`n[7/10] STARTUP ITEMS" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$startupPaths = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
$startupItems = foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | Select-Object Name, FullName, LastWriteTime
    }
}
$startupItems | Export-Csv "$ArtifactDir\startup_items.csv" -NoTypeInformation
Write-Host "Saved startup items"

Write-Host "`n[8/10] RECENT FILES" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-ChildItem C:\Windows\Temp -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
    Select-Object Name, FullName, LastWriteTime, Length |
    Export-Csv "$ArtifactDir\recent_temp_files.csv" -NoTypeInformation
Write-Host "Saved recent file listings"

Write-Host "`n[9/10] WMI PERSISTENCE" -ForegroundColor Yellow
Write-Host "----------------------------------------"
Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
    Export-Csv "$ArtifactDir\wmi_filters.csv" -NoTypeInformation
Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue |
    Export-Csv "$ArtifactDir\wmi_consumers.csv" -NoTypeInformation
Write-Host "Saved WMI subscriptions"

Write-Host "`n[10/10] EVENT LOGS (Last 1000 Security Events)" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$ArtifactDir\security_events.csv" -NoTypeInformation
    Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$ArtifactDir\system_events.csv" -NoTypeInformation
} catch {
    Write-Host "Unable to export some event logs" -ForegroundColor Yellow
}
Write-Host "Saved event logs"

# Create zip archive
Write-Host "`n----------------------------------------"
$zipPath = "$ArtifactDir.zip"
Compress-Archive -Path $ArtifactDir -DestinationPath $zipPath -Force
Write-Host "Created archive: $zipPath" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ARTIFACT COLLECTION COMPLETE" -ForegroundColor Cyan
Write-Host "Artifacts saved to: $ArtifactDir" -ForegroundColor Green
Write-Host "Archive: $zipPath" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
