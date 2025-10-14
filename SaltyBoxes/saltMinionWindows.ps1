<#
.SYNOPSIS
    Salt Minion Universal Installer for Windows.
.DESCRIPTION
    This script downloads the latest Salt Minion installer for Windows,
    prompts the user for the Salt Master IP and an optional Minion ID,
    and performs a silent installation and configuration.
.NOTES
    - Must be run with Administrator privileges.
    - Uses the official Salt Project installer for the 64-bit platform.
#>

$SCRIPT_TITLE = "Salt Minion Universal Installer (Windows)"

Write-Host "#####################################################" -ForegroundColor Cyan
Write-Host "# $SCRIPT_TITLE #" -ForegroundColor Cyan
Write-Host "#####################################################" -ForegroundColor Cyan

# --- Pre-Flight Checks ---

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: This script must be run with Administrator privileges." -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'." -ForegroundColor Red
    Exit 1
}

# --- Configuration Variables ---

# Latest recommended Salt installer URL (adjust version if necessary)
# This link points to the recommended 64-bit installer for the latest version.
$SALT_INSTALLER_URL = "https://repo.saltproject.io/salt/py3/windows/latest-x64.exe"
$INSTALLER_FILENAME = "Salt-Minion-Installer-Latest.exe"
$DOWNLOAD_PATH = Join-Path $env:TEMP $INSTALLER_FILENAME
$SALT_CONFIG_DIR = "C:\salt\conf"

# --- Get User Input ---

# Prompt for Salt Master IP (Mandatory)
$SALT_MASTER_IP = Read-Host "Enter the Salt Master IP address (e.g., 192.168.1.100)"
if ([string]::IsNullOrWhiteSpace($SALT_MASTER_IP)) {
    Write-Host "Error: Salt Master IP address is mandatory. Exiting." -ForegroundColor Red
    Exit 1
}

# Prompt for Minion ID (Optional)
$MINION_ID = Read-Host "Enter a unique Minion ID (Press ENTER to use system hostname)"
if ([string]::IsNullOrWhiteSpace($MINION_ID)) {
    # Use the system's hostname if no ID is provided
    $MINION_ID = $env:COMPUTERNAME
    Write-Host "Using default Minion ID: $MINION_ID" -ForegroundColor Yellow
}


# --- Installation Logic ---

Write-Host "`n--- 1. Downloading Salt Minion Installer ---" -ForegroundColor Green
try {
    # Use Invoke-WebRequest to download the file
    Invoke-WebRequest -Uri $SALT_INSTALLER_URL -OutFile $DOWNLOAD_PATH -ErrorAction Stop
    Write-Host "Successfully downloaded $INSTALLER_FILENAME to $DOWNLOAD_PATH" -ForegroundColor Green
}
catch {
    Write-Host "Error: Failed to download Salt installer from $SALT_INSTALLER_URL." -ForegroundColor Red
    Write-Host "Check network connectivity and URL correctness." -ForegroundColor Red
    Exit 1
}

Write-Host "`n--- 2. Running Silent Installation ---" -ForegroundColor Green

# /S for Silent install
# /master sets the master configuration
# /minion-name sets the minion ID
$INSTALL_ARGUMENTS = @(
    "/S"
    "/master=$SALT_MASTER_IP"
    "/minion-name=$MINION_ID"
)

try {
    # Start the installer process and wait for it to complete
    $process = Start-Process -FilePath $DOWNLOAD_PATH -ArgumentList $INSTALL_ARGUMENTS -Wait -PassThru -ErrorAction Stop

    if ($process.ExitCode -ne 0) {
        Write-Host "Installation failed with Exit Code $($process.ExitCode). Check C:\salt\log\minion.log." -ForegroundColor Red
        Exit 1
    }

    Write-Host "Salt Minion installed successfully." -ForegroundColor Green

}
catch {
    Write-Host "An error occurred during installation: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}


# --- Post-Installation Configuration and Service Start ---

# The installer handles the basic configuration, but we restart the service to ensure
# the new settings take effect immediately.

Write-Host "`n--- 3. Restarting Salt Minion Service ---" -ForegroundColor Green
try {
    # Restart the service (service name is typically 'salt-minion' on Windows)
    Restart-Service -Name 'salt-minion' -ErrorAction Stop
    Write-Host "Service 'salt-minion' restarted and configured to run automatically." -ForegroundColor Green
}
catch {
    Write-Host "Error: Failed to restart the 'salt-minion' service. Check service status manually." -ForegroundColor Red
    # Continue execution to display final steps
}

# --- Final Output ---

Write-Host "`n#####################################################" -ForegroundColor Cyan
Write-Host "# MINION SETUP COMPLETE #" -ForegroundColor Cyan
Write-Host "#####################################################" -ForegroundColor Cyan
Write-Host "Minion ID: $MINION_ID" -ForegroundColor Yellow
Write-Host "Master IP: $SALT_MASTER_IP" -ForegroundColor Yellow
Write-Host ""
Write-Host "NEXT STEP: On your Salt Master, run the following commands:" -ForegroundColor Green
Write-Host "1. List pending keys:" -ForegroundColor White
Write-Host "   sudo salt-key -L" -ForegroundColor DarkGray
Write-Host "2. Accept the new minion key (replace <MINION_ID>):" -ForegroundColor White
Write-Host "   sudo salt-key -a $MINION_ID" -ForegroundColor DarkGray
Write-Host "3. Verify the connection:" -ForegroundColor White
Write-Host "   sudo salt '$MINION_ID' test.ping" -ForegroundColor DarkGray

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeypress")
