<#
.SYNOPSIS
    Automates the deployment of a customized Wazuh single-node stack on Windows,
    offering a choice between Docker, WSL2, or falling back to WSL1 based on system capabilities.

.DESCRIPTION
    This script orchestrates the entire setup process for a custom Wazuh environment.
    It is designed to be run from the root of the 'RnDSweats' repository checkout.

    The script first checks for hardware virtualization support.

    - If virtualization is supported, it prompts the user to choose between:
        a. Deploying Wazuh using Docker Desktop (requires Docker Desktop to be installed and running).
        b. Deploying Wazuh using WSL2 (installs Debian in WSL2).

    - If virtualization is NOT supported, it automatically falls back to deploying
      Wazuh using WSL1 (installs Debian in WSL1).

    Regardless of the chosen deployment method, the script will:
    1. Install necessary Windows features (WSL, Virtual Machine Platform, Hyper-V, Containers).
    2. Install Debian for WSL if not present, or ensure Docker is ready.
    3. Generate and execute a custom script (either in WSL or Docker container) that:
        a. Downloads and runs the official Wazuh installation assistant.
        b. Copies the entire 'RnDSweats' repository into the environment.
        c. Runs the 'fortressInstall.sh' script to add custom rules and decoders.
        d. Runs the 'setConfigs.sh' script to configure the 'linux-default' agent group.
        e. Restarts the Wazuh manager to apply all changes.

.NOTES
    Author: Gemini Code Assist
    - This script MUST be run with Administrator privileges.
    - A system restart may be required if Windows features are enabled for the first time.
    - Assumes this script is located in `RnDSweats/WindowsDev` and run from the `RnDSweats` root.
    - For Docker deployment, Docker Desktop must be installed and running prior to execution.
#>

#Requires -RunAsAdministrator

function Test-VirtualizationSupport {
    Write-Host "--- Checking for Hardware Virtualization Support ---" -ForegroundColor Gray
    $virtInfo = Get-ComputerInfo
    if ($virtInfo.HyperVRequirementVirtualizationFirmwareEnabled -and
        $virtInfo.HyperVRequirementDataExecutionPreventionAvailable -and
        $virtInfo.HyperVRequirementSecondLevelAddressTranslation -and
        $virtInfo.HyperVRequirementVMMonitorModeExtensions) {
        Write-Host "[INFO] Hardware virtualization is supported." -ForegroundColor Green
        return $true
    }
    else {
        Write-Warning "Hardware virtualization is NOT supported or enabled in the BIOS/UEFI."
        if (-not $virtInfo.HyperVRequirementVirtualizationFirmwareEnabled) { Write-Warning " - Reason: Virtualization is not enabled in the firmware (BIOS/UEFI)." }
        if (-not $virtInfo.HyperVRequirementDataExecutionPreventionAvailable) { Write-Warning " - Reason: Data Execution Prevention (DEP) is not available." }
        if (-not $virtInfo.HyperVRequirementSecondLevelAddressTranslation) { Write-Warning " - Reason: Second Level Address Translation (SLAT) is not available." }
        if (-not $virtInfo.HyperVRequirementVMMonitorModeExtensions) { Write-Warning " - Reason: VM Monitor Mode Extensions are not available." }
        return $false
    }
}

function Enable-WindowsFeaturesAndRestart {
    param (
        [string[]]$Features
    )
    $restartNeeded = $false
    foreach ($feature in $Features) {
        if ((Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue).State -ne 'Enabled') {
            Write-Host "Enabling Windows feature: $feature..."
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
            if ($result.RestartNeeded) { $restartNeeded = $true }
        } else {
            Write-Host "Feature '$feature' is already enabled."
        }
    }

    if ($restartNeeded) {
        Write-Warning "A system restart is required to complete the installation of Windows features."
        $choice = Read-Host "Do you want to restart now? (Y/N)"
        if ($choice -match '^[Yy]$') {
            Write-Host "Restarting computer..."
            Restart-Computer -Force
            exit
        } else {
            Write-Error "Please restart your computer and run this script again."
            exit 1
        }
    }
}

function Install-WSLAndDebian {
    param (
        [bool]$UseWSL2 = $false
    )
    Write-Host "=== 1. Enabling WSL and Installing Debian ===" -ForegroundColor Cyan

    $wslFeatures = @("Microsoft-Windows-Subsystem-Linux")
    if ($UseWSL2) {
        $wslFeatures += "VirtualMachinePlatform"
    }
    Enable-WindowsFeaturesAndRestart -Features $wslFeatures

    if ($UseWSL2) {
        wsl --set-default-version 2 | Out-Null
        Write-Host "[SUCCESS] WSL features configured for WSL2." -ForegroundColor Green
    } else {
        Write-Host "[INFO] WSL configured for WSL1." -ForegroundColor Green
    }

    $distroName = "Debian"
    $installed = wsl -l -q | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq $distroName }

    if ($installed) {
        Write-Host "Debian is already installed in WSL." -ForegroundColor Green
    } else {
        Write-Host "Debian not found. Installing now... (This may take a few minutes)"
        wsl --install -d $distroName
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install Debian. Please check your internet connection or run 'wsl --update'."
            exit 1
        }
        Write-Host "[SUCCESS] Debian has been installed." -ForegroundColor Green
    }
}

function Deploy-WazuhOnWSL {
    param (
        [bool]$IsWSL2 = $false
    )
    Write-Host "=== 2. Deploying Custom Wazuh Stack into Debian WSL ===" -ForegroundColor Cyan

    # Define the path to the repository root from where the script is run
    $repoRoot = (Get-Location).Path
    $wslRepoPath = "/root/RnDSweats" # Where the repo will be copied inside WSL

    # The shell script that will be generated and run inside WSL
    $wslScript = @"
#!/bin/bash
set -e

echo '--- [WSL] Starting Wazuh Installation ---'

# Update package list
apt-get update

# Install dependencies for scripts
apt-get install -y curl git

# Download and run the Wazuh installation assistant
echo '--- [WSL] Downloading and running Wazuh installer... ---'
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
bash ./wazuh-install.sh -a

# Copy the repository content into WSL for the custom scripts
echo '--- [WSL] Copying repository for custom configurations... ---'
mkdir -p /root
cp -R '$repoRoot' /root/

# Run the SOCFortress custom rules installation script
echo '--- [WSL] Running fortressInstall.sh... ---'
bash ${wslRepoPath}/Tools/Wazuh/fortressInstall.sh

# Run the group configuration script
echo '--- [WSL] Running setConfigs.sh... ---'
bash ${wslRepoPath}/Tools/Wazuh/Configs/setConfigs.sh

# Restart the manager to apply all new rules and configurations
echo '--- [WSL] Restarting wazuh-manager... ---'
# Check for systemd; use 'service' as a fallback for WSL1
if [ -d /run/systemd/system ]; then
    echo '--- [WSL] Restarting services via systemctl (WSL2 detected)... ---'
    systemctl restart wazuh-manager
else
    echo '--- [WSL] Restarting services via init.d scripts (WSL1 detected)... ---'
    # The all-in-one installer may not work correctly on WSL1, but we attempt to restart the manager anyway
    service wazuh-manager restart || echo "Could not restart wazuh-manager via 'service' command."
fi
echo '--- [WSL] Custom Wazuh deployment complete! ---'

"@

    Write-Host "Generated setup script. Now executing inside Debian WSL..."
    # Execute the script block inside the Debian WSL instance as root
    wsl -d Debian -u root -- /bin/bash -c $wslScript

    Write-Host "[SUCCESS] Wazuh deployment script has finished." -ForegroundColor Green
    Write-Host "You can access the Wazuh Dashboard from your browser. Check the installation summary for the password."
}

function Test-DockerPrerequisites {
    Write-Host "--- Checking for Docker Prerequisites ---" -ForegroundColor Gray
    
    $dockerExists = Get-Command docker -ErrorAction SilentlyContinue
    $composeExists = Get-Command docker-compose -ErrorAction SilentlyContinue

    if (-not $dockerExists) {
        Write-Error "Docker command not found. Please install Docker Desktop and ensure it is running."
        return $false
    }
    if (-not $composeExists) {
        Write-Error "Docker Compose command not found. Please ensure Docker Desktop is installed correctly."
        return $false
    }

    Write-Host "[SUCCESS] Docker and Docker Compose are available." -ForegroundColor Green
    return $true
}

function Deploy-WazuhOnDocker {
    Write-Host "=== 2. Deploying Custom Wazuh Stack in Docker ===" -ForegroundColor Cyan

    # Ensure Docker prerequisites are met
    if (-not (Test-DockerPrerequisites)) {
        Write-Error "Docker prerequisites not met. Cannot proceed with Docker deployment."
        exit 1
    }

    # Setup working directory
    $wazuhDockerDir = "C:\Wazuh-Docker"
    if (-not (Test-Path -Path $wazuhDockerDir)) {
        New-Item -Path $wazuhDockerDir -ItemType Directory | Out-Null
    }
    Set-Location -Path $wazuhDockerDir
    Write-Host "Working directory set to $wazuhDockerDir"

    # Download docker-compose.yml
    $composeUrl = "https://raw.githubusercontent.com/wazuh/wazuh-docker/master/single-node/docker-compose.yml"
    $composeFile = "docker-compose.yml"
    Write-Host "Downloading Wazuh docker-compose.yml..."
    try {
        Invoke-WebRequest -Uri $composeUrl -OutFile $composeFile
    }
    catch {
        Write-Error "Failed to download docker-compose.yml. Please check your internet connection. Error: $($_.Exception.Message)"
        exit 1
    }

    # Start the Wazuh stack
    Write-Host "Starting Wazuh Docker containers... (This may take several minutes on first run)"
    docker-compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Error "docker-compose up failed. Please check the Docker logs."
        exit 1
    }

    # Wait for the manager to be ready. This is a critical step.
    $waitTime = 120 # seconds
    Write-Host "Waiting ${waitTime}s for the Wazuh manager to initialize before applying customizations..."
    Start-Sleep -Seconds $waitTime

    # Get the path to the repository root from where the script is run
    $repoRoot = (Get-Location -PSProvider FileSystem).Path
    $containerName = "wazuh-1" # Default name from the official compose file
    $dockerRepoPath = "/tmp/RnDSweats"

    Write-Host "Copying repository content into the '$containerName' container..."
    docker cp "$repoRoot" "${containerName}:$dockerRepoPath"

    Write-Host "Executing custom scripts inside the container..."
    
    # Run the SOCFortress custom rules installation script
    Write-Host "--- Running fortressInstall.sh..."
    docker exec $containerName bash "${dockerRepoPath}/Tools/Wazuh/fortressInstall.sh"

    # Run the group configuration script
    Write-Host "--- Running setConfigs.sh..."
    docker exec $containerName bash "${dockerRepoPath}/Tools/Wazuh/Configs/setConfigs.sh"

    # Restart the manager to apply all new rules and configurations
    Write-Host "Restarting the wazuh-manager service inside the container..."
    docker exec $containerName systemctl restart wazuh-manager

    Write-Host "[SUCCESS] Custom Wazuh deployment in Docker is complete." -ForegroundColor Green
    Write-Host "You can access the Wazuh Dashboard at: https://localhost"
    Write-Host "Default credentials are user: admin, password: SecretPassword"
}

# --- Main Script Logic ---

$isVirtSupported = Test-VirtualizationSupport

if ($isVirtSupported) {
    Write-Host "Hardware virtualization is supported. You have deployment options:" -ForegroundColor Green
    Write-Host "1. Deploy Wazuh using Docker Desktop (requires Docker Desktop installed and running)."
    Write-Host "2. Deploy Wazuh using WSL2."
    Write-Host "Enter your choice (1 or 2):"

    $choice = Read-Host

    switch ($choice) {
        "1" {
            Write-Host "Attempting Docker deployment..." -ForegroundColor Yellow
            Deploy-WazuhOnDocker
        }
        "2" {
            Write-Host "Attempting WSL2 deployment..." -ForegroundColor Yellow
            Install-WSLAndDebian -UseWSL2 $true
            Deploy-WazuhOnWSL -IsWSL2 $true
        }
        default {
            Write-Error "Invalid choice. Please run the script again and select 1 or 2."
            exit 1
        }
    }
} else {
    Write-Warning "Hardware virtualization is NOT supported. Falling back to WSL1 deployment."
    Write-Warning "Docker and WSL2 are not available without virtualization."
    Install-WSLAndDebian -UseWSL2 $false
    Deploy-WazuhOnWSL -IsWSL2 $false
}

Write-Host "Overall script execution finished." -ForegroundColor Green