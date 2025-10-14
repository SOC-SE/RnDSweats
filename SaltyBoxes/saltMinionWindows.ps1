<#
.SYNOPSIS
    Installs the Salt Minion on Windows using a direct MSI link and msiexec.
.DESCRIPTION
    This script automates the Salt Minion installation by:
    - Verifying it is running with Administrator privileges.
    - Prompting for the Salt Master's IP and an optional Minion ID.
    - Downloading a specific Salt Minion MSI installer.
    - Using msiexec to perform a quiet installation with the provided configuration.
    - Ensuring the salt-minion service is enabled and started.
.NOTES
    Author: Samuel Brucker 2025-2026
    Version: 1.1
    Created: 10/14/2025
#>

# --- Script Title ---
Write-Host "#####################################################" -ForegroundColor Green
Write-Host "# Salt Minion Installer (Windows)                   #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host

# --- Pre-Flight Checks ---

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run with Administrator privileges."
    Write-Warning "Please right-click the script and select 'Run as Administrator' or run from an elevated PowerShell prompt."
    Read-Host "Press Enter to exit..."
    exit 1
}

# --- Get User Input ---

# Prompt for Salt Master IP (Mandatory)
$SALT_MASTER_IP = Read-Host -Prompt "Enter the Salt Master IP address (e.g., 192.168.1.100)"

if ([string]::IsNullOrWhiteSpace($SALT_MASTER_IP)) {
    Write-Error "Salt Master IP address is mandatory. Exiting."
    Read-Host "Press Enter to exit..."
    exit 1
}

# Prompt for Minion ID (Optional)
$MINION_ID = Read-Host -Prompt "Enter a unique Minion ID (Press ENTER to use system hostname)"

# If MINION_ID is empty, use the system's hostname
if ([string]::IsNullOrWhiteSpace($MINION_ID)) {
    $MINION_ID = $env:COMPUTERNAME
    Write-Host "Using default Minion ID: $MINION_ID"
}

# --- Installation Logic ---

# Define the installer URL and local file path
$installerUrl = "https://packages.broadcom.com/artifactory/saltproject-generic/windows/3007.8/Salt-Minion-3007.8-Py3-AMD64.msi"
$installerFileName = "Salt-Minion-3007.8-Py3-x86.msi"
$downloadPath = Join-Path $env:TEMP $installerFileName

try {
    Write-Host "`n--- Downloading Salt Minion Installer ---" -ForegroundColor Cyan
    Write-Host "From: $installerUrl"
    
    # Download the installer file
    Invoke-WebRequest -Uri $installerUrl -OutFile $downloadPath
    
    Write-Host "`n--- Installing $installerFileName ---" -ForegroundColor Cyan
    Write-Host "This may take a few moments..."
    
    # Define arguments for msiexec quiet installation
    # /i <file>     - Specifies the installer file
    # /quiet        - Suppresses the installer UI
    # /norestart    - Prevents the system from restarting after installation
    # MASTER=...    - Sets the Salt Master address
    # MINION_ID=... - Sets the Minion ID
    $msiArgs = "/i `"$downloadPath`" /quiet /norestart MASTER=$SALT_MASTER_IP MINION_ID=$MINION_ID"
    
    # Execute msiexec and wait for it to complete
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    
    # Check the exit code from the installer
    if ($process.ExitCode -ne 0) {
        Write-Error "The installer exited with code: $($process.ExitCode). Check msiexec logs for details."
        throw "Installation failed."
    } else {
        Write-Host "Installation completed successfully."
    }

    # --- Service Configuration ---
    
    Write-Host "`n--- Configuring Minion Service ---" -ForegroundColor Cyan
    $serviceName = "salt-minion"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-Host "Setting the '$serviceName' service to start automatically."
        Set-Service -Name $serviceName -StartupType Automatic
        
        Write-Host "Starting the '$serviceName' service..."
        Start-Service -Name $serviceName
    } else {
        Write-Warning "Could not find the '$serviceName' service. It may not have been installed correctly."
    }

}
catch {
    Write-Error "An error occurred during the installation process: $_"
    Read-Host "Press Enter to exit..."
    exit 1
}
finally {
    # Clean up the downloaded installer file
    if (Test-Path -Path $downloadPath) {
        Write-Host "`n--- Cleaning up temporary files ---" -ForegroundColor Cyan
        Remove-Item -Path $downloadPath -Force
        Write-Host "Removed installer file: $downloadPath"
    }
}


# --- Final Output ---
Write-Host "`n#####################################################" -ForegroundColor Green
Write-Host "# MINION SETUP COMPLETE                             #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host
Write-Host "Minion ID configured as: $MINION_ID"
Write-Host "Master IP configured as: $SALT_MASTER_IP"
Write-Host
Write-Host "NEXT STEP: On your Salt Master, run the following commands:" -ForegroundColor Yellow
Write-Host "1. List pending keys:" -ForegroundColor Yellow
Write-Host "   sudo salt-key -L" -ForegroundColor White
Write-Host "2. Accept the new minion key:" -ForegroundColor Yellow
Write-Host "   sudo salt-key -a $MINION_ID" -ForegroundColor White
Write-Host "3. Verify the connection:" -ForegroundColor Yellow
Write-Host "   sudo salt '$MINION_ID' test.ping" -ForegroundColor White
Write-Host

Read-Host "Press Enter to exit..."