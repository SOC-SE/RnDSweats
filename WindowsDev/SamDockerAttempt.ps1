<#
.SYNOPSIS
    Installs Docker Engine on a Windows Server if virtualization is supported,
    otherwise installs Windows Subsystem for Linux (WSL1).

.DESCRIPTION
    This script first checks if the host server has the necessary hardware
    virtualization capabilities (like Intel VT-x or AMD-V) enabled in the firmware.

    - If virtualization is supported, it proceeds to install the Docker Engine
      for Windows Server, which is required for running native Windows containers.

    - If virtualization is NOT supported, it explains that neither Docker nor WSL2
      can be installed, and instead installs WSL1, which does not have this
      hardware dependency.

.NOTES
    Author: Gemini Code Assist
    Run this script with Administrator privileges.
    A system restart may be required during the installation process.
#>

#Requires -RunAsAdministrator

function Test-VirtualizationSupport {
    Write-Host "=== 1. Checking for Hardware Virtualization Support ===" -ForegroundColor Cyan
    $virtInfo = Get-ComputerInfo
    if ($virtInfo.HyperVRequirementVirtualizationFirmwareEnabled -and
        $virtInfo.HyperVRequirementDataExecutionPreventionAvailable -and
        $virtInfo.HyperVRequirementSecondLevelAddressTranslation -and
        $virtInfo.HyperVRequirementVMMonitorModeExtensions) {
        Write-Host "[SUCCESS] Hardware virtualization is supported on this server." -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "[FAILURE] Hardware virtualization is NOT supported or enabled in the BIOS/UEFI." -ForegroundColor Red
        Write-Host "The following requirements were not met:"
        if (-not $virtInfo.HyperVRequirementVirtualizationFirmwareEnabled) { Write-Warning " - Virtualization is not enabled in the firmware (BIOS/UEFI)." }
        if (-not $virtInfo.HyperVRequirementDataExecutionPreventionAvailable) { Write-Warning " - Data Execution Prevention (DEP) is not available." }
        if (-not $virtInfo.HyperVRequirementSecondLevelAddressTranslation) { Write-Warning " - Second Level Address Translation (SLAT) is not available." }
        if (-not $virtInfo.HyperVRequirementVMMonitorModeExtensions) { Write-Warning " - VM Monitor Mode Extensions are not available." }
        return $false
    }
}

function Install-DockerEngine {
    Write-Host "=== 2. Installing Docker Engine for Windows Server ===" -ForegroundColor Cyan

    # Enable required Windows features
    Write-Host "Enabling Hyper-V and Containers features..."
    try {
        Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart:$false | Out-Null
        $ctResult = Install-WindowsFeature -Name Containers
    }
    catch {
        Write-Error "Failed to enable Windows features. Please check the logs. Error: $($_.Exception.Message)"
        exit 1
    }

    if ($ctResult.RestartNeeded) {
        Write-Warning "A restart is required to complete feature installation."
        $choice = Read-Host "Do you want to restart now? (Y/N)"
        if ($choice -match '^[Yy]$') {
            Write-Host "Restarting computer..."
            Restart-Computer -Force
            # The script will exit here and needs to be re-run after restart.
            exit
        }
        else {
            Write-Error "A restart is required. Please restart the server and run the script again."
            exit 1
        }
    }

    # Install Docker
    Write-Host "Installing the DockerMsftProvider PowerShell module..."
    if (-not (Get-Module -ListAvailable -Name DockerMsftProvider)) {
        Install-Module -Name DockerMsftProvider -Repository PSGallery -Force -Confirm:$false
    }

    Write-Host "Installing Docker package..."
    Install-Package -Name docker -ProviderName DockerMsftProvider -Force

    Write-Host "Starting and enabling the Docker service..."
    Start-Service docker
    Set-Service docker -StartupType Automatic

    Write-Host "[SUCCESS] Docker Engine installation is complete." -ForegroundColor Green
    Write-Host "You can test the installation by running: docker version"
}

function Install-WSL1 {
    Write-Host "=== 2. Installing Windows Subsystem for Linux (WSL1) ===" -ForegroundColor Cyan
    Write-Warning "Hardware virtualization is required for both Docker and WSL2."
    Write-Host "As a fallback, this script will now install WSL1."

    # Enable the WSL feature
    Write-Host "Enabling the 'Windows Subsystem for Linux' feature..."
    try {
        dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    }
    catch {
        Write-Error "Failed to enable the WSL feature. Error: $($_.Exception.Message)"
        exit 1
    }

    # Check if a restart is needed. DISM exit code 3010 means restart required.
    if ($LASTEXITCODE -eq 3010) {
        Write-Warning "A restart is required to complete the installation of WSL."
        $choice = Read-Host "Do you want to restart now? (Y/N)"
        if ($choice -match '^[Yy]$') {
            Write-Host "Restarting computer..."
            Restart-Computer -Force
            exit
        }
        else {
            Write-Error "A restart is required. Please restart the server to use WSL."
            exit 1
        }
    }

    Write-Host "[SUCCESS] WSL1 feature has been enabled." -ForegroundColor Green
    Write-Host "After restarting (if prompted), you can install a Linux distribution from the Microsoft Store"
    Write-Host "or by using 'wsl --install -d <DistroName>' on newer systems."
}

# --- Main Script Logic ---

if (Test-VirtualizationSupport) {
    # If virtualization is supported, install Docker Engine
    Install-DockerEngine
}
else {
    # If virtualization is not supported, install WSL1 as a fallback
    Install-WSL1
}

Write-Host "Script execution finished."