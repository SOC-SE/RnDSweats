<#
.SYNOPSIS
    Installs the Salt Minion on Windows using the official Broadcom MSI.
.DESCRIPTION
    Automates Salt Minion installation:
    - Verifies Administrator privileges.
    - Prompts for Salt Master IP (with default).
    - Detects OS Architecture (64-bit vs 32-bit).
    - Downloads the correct MSI from the Broadcom repository.
    - Performs a quiet install with logging.
    - Configures Windows Firewall exceptions.
    - Starts the service.
#>

# --- Configuration ---
$DEFAULT_MASTER_IP = "172.20.242.20"
$SALT_VERSION = "3007.8"

# --- Script Title ---
Write-Host "#####################################################" -ForegroundColor Green
Write-Host "# Salt Minion Installer (Windows)                   #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host

# --- 1. Pre-Flight Checks ---

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run with Administrator privileges."
    Write-Warning "Please right-click the script and select 'Run as Administrator'."
    Read-Host "Press Enter to exit..."
    exit 1
}

# --- 2. User Input ---

# Prompt for Salt Master IP
$inputIP = Read-Host -Prompt "Enter Salt Master IP [Default: $DEFAULT_MASTER_IP]"
if ([string]::IsNullOrWhiteSpace($inputIP)) {
    $SALT_MASTER_IP = $DEFAULT_MASTER_IP
} else {
    $SALT_MASTER_IP = $inputIP
}
Write-Host "Using Master IP: $SALT_MASTER_IP" -ForegroundColor Cyan

# Prompt for Minion ID
$inputID = Read-Host -Prompt "Enter a unique Minion ID (Press ENTER to use system hostname)"
if ([string]::IsNullOrWhiteSpace($inputID)) {
    $MINION_ID = $env:COMPUTERNAME
} else {
    $MINION_ID = $inputID
}
Write-Host "Using Minion ID: $MINION_ID" -ForegroundColor Cyan

# --- 3. Architecture Detection & URL Selection ---

if ([Environment]::Is64BitOperatingSystem) {
    Write-Host "Detected 64-bit Operating System."
    $arch = "AMD64"
} else {
    Write-Host "Detected 32-bit Operating System."
    $arch = "x86"
}

# Construct URL based on architecture (Broadcom Repo Structure)
$installerFileName = "Salt-Minion-$SALT_VERSION-Py3-$arch.msi"
$installerUrl = "https://packages.broadcom.com/artifactory/saltproject-generic/windows/$SALT_VERSION/$installerFileName"
$downloadPath = Join-Path $env:TEMP $installerFileName
$logPath = Join-Path $env:TEMP "salt_install.log"

# --- 4. Installation Logic ---

try {
    Write-Host "`n--- Downloading Salt Minion Installer ---" -ForegroundColor Cyan
    Write-Host "Source: $installerUrl"
    Write-Host "Dest:   $downloadPath"
    
    # Download the installer file (Using TLS 1.2 is often required for modern repos)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $installerUrl -OutFile $downloadPath -ErrorAction Stop
    
    Write-Host "`n--- Installing Salt Minion ---" -ForegroundColor Cyan
    Write-Host "Installing version $SALT_VERSION... (This may take a minute)"
    
    # Define arguments for msiexec
    # /log ...      - Creates a verbose log file for troubleshooting
    # MASTER=...    - Sets the Master IP in the config
    # MINION_ID=... - Sets the Minion ID in the config
    # START_MINION= - We set this to 1 to auto-start, but we check service later anyway
    $msiArgs = "/i `"$downloadPath`" /quiet /norestart /log `"$logPath`" MASTER=$SALT_MASTER_IP MINION_ID=$MINION_ID START_MINION=1"
    
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Error "Installer exited with code: $($process.ExitCode)."
        Write-Warning "Check the log file for details: $logPath"
        throw "Installation failed."
    } else {
        Write-Host "Installation completed successfully." -ForegroundColor Green
    }

    # --- 5. Firewall Configuration ---
    # Ensure Windows Firewall allows the salt-minion process
    Write-Host "`n--- Configuring Firewall ---" -ForegroundColor Cyan
    $saltExe = "C:\Program Files\Salt Project\Salt\bin\salt-minion.exe" # Default 3007 path
    
    if (Test-Path $saltExe) {
        New-NetFirewallRule -DisplayName "Salt Minion" -Direction Inbound -Program $saltExe -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Added Firewall exception for Salt Minion."
    } else {
        Write-Warning "Could not find salt-minion.exe at default path. Skipping firewall rule."
    }

    # --- 6. Service Configuration ---
    
    Write-Host "`n--- Verifying Service ---" -ForegroundColor Cyan
    $serviceName = "salt-minion"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($service) {
        Set-Service -Name $serviceName -StartupType Automatic
        if ($service.Status -ne 'Running') {
            Start-Service -Name $serviceName
        }
        Write-Host "Service '$serviceName' is $($service.Status)." -ForegroundColor Green
    } else {
        Write-Warning "Service '$serviceName' not found."
    }

}
catch {
    Write-Error "An error occurred: $_"
    Read-Host "Press Enter to exit..."
    exit 1
}
finally {
    # Cleanup
    if (Test-Path -Path $downloadPath) {
        Remove-Item -Path $downloadPath -Force
    }
}

# --- Final Output ---
Write-Host "`n#####################################################" -ForegroundColor Green
Write-Host "# MINION SETUP COMPLETE                             #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host
Write-Host "Minion ID: $MINION_ID"
Write-Host "Master IP: $SALT_MASTER_IP"
Write-Host

Read-Host "Press Enter to exit..."