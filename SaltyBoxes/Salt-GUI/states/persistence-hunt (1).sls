# CCDC Windows Persistence Hunter State
# Scans for common persistence mechanisms on Windows
# Compatible with: Windows Server 2016, 2019, 2022, Windows 10/11

# Create output directory
create-output-dir:
  cmd.run:
    - name: 'New-Item -ItemType Directory -Force -Path C:\CCDC-Persistence'
    - shell: powershell

# Scan Run keys
scan-run-keys:
  cmd.run:
    - name: |
        $output = "=== Registry Run Keys ===" 
        $output += "`n`n--- HKLM\Software\Microsoft\Windows\CurrentVersion\Run ---`n"
        $output += Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-String
        $output += "`n--- HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce ---`n"
        $output += Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Out-String
        $output += "`n--- HKCU Run Keys (all users) ---`n"
        Get-ChildItem "C:\Users" -Directory | ForEach-Object {
            $ntuser = "$($_.FullName)\NTUSER.DAT"
            $output += "`nUser: $($_.Name)`n"
        }
        $output += "`n--- HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run ---`n"
        $output += Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-String
        $output | Out-File -FilePath "C:\CCDC-Persistence\run-keys.txt" -Encoding UTF8
    - shell: powershell

# Scan scheduled tasks
scan-scheduled-tasks:
  cmd.run:
    - name: |
        $output = "=== Scheduled Tasks ===" 
        $output += "`n`n--- All Scheduled Tasks ---`n"
        $output += Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName, TaskPath, State -AutoSize | Out-String
        $output += "`n`n--- Task Details (non-Microsoft) ---`n"
        Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"} | ForEach-Object {
            $output += "`n=== $($_.TaskName) ===`n"
            $output += $_ | Get-ScheduledTaskInfo | Out-String
            $output += ($_ | Select-Object -ExpandProperty Actions | Out-String)
        }
        $output | Out-File -FilePath "C:\CCDC-Persistence\scheduled-tasks.txt" -Encoding UTF8
    - shell: powershell

# Scan services
scan-services:
  cmd.run:
    - name: |
        $output = "=== Windows Services ===" 
        $output += "`n`n--- Running Services ---`n"
        $output += Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table Name, DisplayName, StartType -AutoSize | Out-String
        $output += "`n`n--- Non-standard Services (manual review needed) ---`n"
        $output += Get-WmiObject win32_service | Where-Object {$_.PathName -notlike "*System32*" -and $_.PathName -notlike "*SysWOW64*"} | Format-Table Name, State, PathName -AutoSize | Out-String
        $output += "`n`n--- Services with unusual paths ---`n"
        $output += Get-WmiObject win32_service | Where-Object {$_.PathName -like "*Users*" -or $_.PathName -like "*Temp*" -or $_.PathName -like "*AppData*"} | Format-Table Name, State, PathName -AutoSize | Out-String
        $output | Out-File -FilePath "C:\CCDC-Persistence\services.txt" -Encoding UTF8
    - shell: powershell

# Scan startup folders
scan-startup-folders:
  cmd.run:
    - name: |
        $output = "=== Startup Folders ===" 
        $output += "`n`n--- All Users Startup ---`n"
        $output += Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Format-Table Name, LastWriteTime, Length -AutoSize | Out-String
        $output += "`n`n--- Per-User Startup Folders ---`n"
        Get-ChildItem "C:\Users" -Directory | ForEach-Object {
            $startupPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            if (Test-Path $startupPath) {
                $items = Get-ChildItem $startupPath -ErrorAction SilentlyContinue
                if ($items) {
                    $output += "`nUser: $($_.Name)`n"
                    $output += $items | Format-Table Name, LastWriteTime -AutoSize | Out-String
                }
            }
        }
        $output | Out-File -FilePath "C:\CCDC-Persistence\startup-folders.txt" -Encoding UTF8
    - shell: powershell

# Scan WMI subscriptions
scan-wmi:
  cmd.run:
    - name: |
        $output = "=== WMI Event Subscriptions ===" 
        $output += "`n`n--- Event Filters ---`n"
        $output += Get-WmiObject -Namespace root\Subscription -Class __EventFilter | Format-List * | Out-String
        $output += "`n`n--- Event Consumers ---`n"
        $output += Get-WmiObject -Namespace root\Subscription -Class __EventConsumer | Format-List * | Out-String
        $output += "`n`n--- Filter-Consumer Bindings ---`n"
        $output += Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Format-List * | Out-String
        $output | Out-File -FilePath "C:\CCDC-Persistence\wmi-subscriptions.txt" -Encoding UTF8
    - shell: powershell

# Scan local users and groups
scan-users:
  cmd.run:
    - name: |
        $output = "=== Local Users and Groups ===" 
        $output += "`n`n--- Local Users ---`n"
        $output += Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet -AutoSize | Out-String
        $output += "`n`n--- Administrators Group ---`n"
        $output += Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Format-Table Name, ObjectClass, PrincipalSource | Out-String
        $output += "`n`n--- Remote Desktop Users ---`n"
        $output += Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Format-Table Name, ObjectClass | Out-String
        $output += "`n`n--- All Local Groups with Members ---`n"
        Get-LocalGroup | ForEach-Object {
            $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
            if ($members) {
                $output += "`n--- $($_.Name) ---`n"
                $output += $members | Format-Table Name, ObjectClass | Out-String
            }
        }
        $output | Out-File -FilePath "C:\CCDC-Persistence\users-groups.txt" -Encoding UTF8
    - shell: powershell

# Scan network connections
scan-network:
  cmd.run:
    - name: |
        $output = "=== Network Connections ===" 
        $output += "`n`n--- Listening Ports ---`n"
        $output += Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} -AutoSize | Out-String
        $output += "`n`n--- Established Connections ---`n"
        $output += Get-NetTCPConnection -State Established | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} -AutoSize | Out-String
        $output += "`n`n--- DNS Cache ---`n"
        $output += Get-DnsClientCache | Format-Table Entry, Data -AutoSize | Out-String
        $output | Out-File -FilePath "C:\CCDC-Persistence\network.txt" -Encoding UTF8
    - shell: powershell

# Scan for suspicious processes
scan-processes:
  cmd.run:
    - name: |
        $output = "=== Running Processes ===" 
        $output += "`n`n--- All Processes with Path ---`n"
        $output += Get-Process | Where-Object {$_.Path} | Sort-Object ProcessName | Format-Table ProcessName, Id, Path -AutoSize | Out-String
        $output += "`n`n--- Processes from User Directories ---`n"
        $output += Get-Process | Where-Object {$_.Path -like "*Users*" -or $_.Path -like "*Temp*" -or $_.Path -like "*AppData*"} | Format-Table ProcessName, Id, Path | Out-String
        $output += "`n`n--- Processes with Network Connections ---`n"
        $netProcs = Get-NetTCPConnection | Select-Object -ExpandProperty OwningProcess -Unique
        $output += Get-Process | Where-Object {$_.Id -in $netProcs} | Format-Table ProcessName, Id, Path | Out-String
        $output | Out-File -FilePath "C:\CCDC-Persistence\processes.txt" -Encoding UTF8
    - shell: powershell

# Check for DLL hijacking opportunities
scan-dll-paths:
  cmd.run:
    - name: |
        $output = "=== DLL Search Path Check ===" 
        $output += "`n`n--- PATH Environment Variable ---`n"
        $output += $env:PATH -split ";" | Out-String
        $output += "`n`n--- Writable Paths in PATH ---`n"
        $env:PATH -split ";" | ForEach-Object {
            $acl = Get-Acl $_ -ErrorAction SilentlyContinue
            if ($acl) {
                $writable = $acl.Access | Where-Object {$_.FileSystemRights -match "Write" -and $_.IdentityReference -match "Users|Everyone|Authenticated"}
                if ($writable) {
                    $output += "`nWRITABLE: $_`n"
                }
            }
        }
        $output | Out-File -FilePath "C:\CCDC-Persistence\dll-paths.txt" -Encoding UTF8
    - shell: powershell

# Generate summary
generate-summary:
  cmd.run:
    - name: |
        $output = "=== CCDC Persistence Hunt Summary ===" 
        $output += "`nGenerated: $(Get-Date)"
        $output += "`nHostname: $env:COMPUTERNAME"
        $output += "`n`nFiles generated in C:\CCDC-Persistence\:"
        $output += Get-ChildItem "C:\CCDC-Persistence" | Format-Table Name, Length, LastWriteTime | Out-String
        $output += "`n`nREVIEW EACH FILE FOR SUSPICIOUS ENTRIES!"
        $output | Out-File -FilePath "C:\CCDC-Persistence\SUMMARY.txt" -Encoding UTF8
        Get-Content "C:\CCDC-Persistence\SUMMARY.txt"
    - shell: powershell
