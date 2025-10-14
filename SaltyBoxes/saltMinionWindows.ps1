<#
.SYNOPSIS
    A universal script to install the Salt Minion on Windows systems.
.DESCRIPTION
    This PowerShell script automates the Salt Minion installation process on Windows. It:
    - Verifies it is running with Administrator privileges.
    - Prompts for the Salt Master's IP address and an optional Minion ID.
    - Automatically detects and downloads the latest 64-bit Salt Minion installer.
    - Performs a silent installation, configuring the master and minion ID.
    - Enables and restarts the salt-minion service.
    - Provides instructions for accepting the key on the Salt Master.
.NOTES
    Author: Samuel Brucker 2025 - 2026
    Version: 1.0
    Created: 10/14/2025
#>

# --- Script Title ---
Write-Host "#####################################################" -ForegroundColor Green
Write-Host "# Salt Minion Universal Installer (Windows)         #" -ForegroundColor Green
Write-Host "#####################################################" -ForegroundColor Green
Write-Host

# --- Pre-Flight Checks ---

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run with Administrator privileges."
    Write-Warning "Please right-click the script and select 'Run as Administrator' or run from an elevated PowerShell prompt."
    # Pause to allow the user to read the error before the window closes
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

# If MINION_ID is empty, Salt will default to the system's hostname
if ([string]::IsNullOrWhiteSpace($MINION_ID)) {
    $MINION_ID = $env:COMPUTERNAME
    Write-Host "Using default Minion ID: $MINION_ID"
}

# --- Installation Logic ---

try {
    Write-Host "`n--- Locating the latest Salt Minion installer ---" -ForegroundColor Cyan
    
    # URL to the YAML file containing the latest installer info
    $latestYmlUrl = "https://repo.saltproject.io/salt/py3/windows/latest/latest.yml"
    
    # Download the YAML content and parse out the installer's file name
    $ymlContent = Invoke-WebRequest -Uri $latestYmlUrl -UseBasicParsing | Select-Object -ExpandProperty Content
    $installerFileName = ($ymlContent | Select-String -Pattern "path:\s+(Salt-Minion-.*-Py3-AMD64-Setup\.exe)" | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()

    if ([string]::IsNullOrWhiteSpace($installerFileName)) {
         Write-Error "Could not automatically determine the latest installer file name. Exiting."
         throw "Installer detection failed."
    }

    $installerUrl = "https://repo.saltproject.io/salt/py3/windows/latest/$installerFileName"
    $downloadPath = Join-Path $env:TEMP $installerFileName
    
    Write-Host "Found installer: $installerFileName"
    Write-Host "Downloading from: $installerUrl"
    
    # Download the installer file
    Invoke-WebRequest -Uri $installerUrl -OutFile $downloadPath
    
    Write-Host "`n--- Installing $installerFileName ---" -ForegroundColor Cyan
    Write-Host "This may take a few moments..."
    
    # Define arguments for silent installation
    # /S             - Silent mode
    # /master=<ip>   - Sets the Salt Master address
    # /minion-id=<id>- Sets the Minion ID
    # /start-minion=1- Ensures the minion service starts after installation
    $installArgs = "/S /master=$SALT_MASTER_IP /minion-id=$MINION_ID /start-minion=1"
    
    # Execute the installer silently and wait for it to complete
    $process = Start-Process -FilePath $downloadPath -ArgumentList $installArgs -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Error "The installer exited with a non-zero exit code: $($process.ExitCode). Installation may have failed."
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
        
        Write-Host "Restarting the '$serviceName' service to apply configuration..."
        Restart-Service -Name $serviceName
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