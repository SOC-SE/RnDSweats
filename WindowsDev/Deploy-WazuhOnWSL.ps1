<#
.SYNOPSIS
    Automates the deployment of a customized Wazuh single-node stack on Windows,
    intelligently using WSL2 if virtualization is available, or falling back to WSL1.

.DESCRIPTION
    This script orchestrates the entire setup process for a custom Wazuh environment.
    It is designed to be run from the root of the 'RnDSweats' repository checkout.

    The script performs the following actions:
    1. Checks for and enables the necessary Windows features (WSL, Virtual Machine Platform).
       - It will attempt to use WSL2 if hardware virtualization is supported.
       - If not, it will warn the user and fall back to the more compatible WSL1.
    2. Installs the Debian distribution for WSL if not already present.
    3. Generates a custom shell script to run inside the new Debian instance.
    4. Executes the shell script, which will:
        a. Download and run the official Wazuh installation assistant.
        b. Copy the entire 'RnDSweats' repository into the WSL instance.
        c. Run the 'fortressInstall.sh' script to add custom rules and decoders.
        d. Run the 'setConfigs.sh' script to configure the 'linux-default' agent group.
        e. Restart the Wazuh manager to apply all changes.

.NOTES
    Author: Gemini Code Assist
    - This script MUST be run with Administrator privileges.
    - A system restart may be required if WSL features are enabled for the first time.
    - Assumes this script is located in `RnDSweats/WindowsDev` and run from the `RnDSweats` root.
#>

#Requires -RunAsAdministrator

function Test-VirtualizationSupport {
    Write-Host "--- Checking for Hardware Virtualization Support (for WSL2) ---" -ForegroundColor Gray
    $virtInfo = Get-ComputerInfo
    if ($virtInfo.HyperVRequirementVirtualizationFirmwareEnabled -and
        $virtInfo.HyperVRequirementDataExecutionPreventionAvailable -and
        $virtInfo.HyperVRequirementSecondLevelAddressTranslation -and
        $virtInfo.HyperVRequirementVMMonitorModeExtensions) {
        Write-Host "[INFO] Hardware virtualization is supported. WSL2 will be used." -ForegroundColor Green
        return $true
    }
    else {
        Write-Warning "Hardware virtualization is NOT supported or enabled in the BIOS/UEFI."
        Write-Warning "Falling back to WSL1. The modern Wazuh installer may have issues without systemd."
        if (-not $virtInfo.HyperVRequirementVirtualizationFirmwareEnabled) { Write-Warning " - Reason: Virtualization is not enabled in the firmware (BIOS/UEFI)." }
        if (-not $virtInfo.HyperVRequirementDataExecutionPreventionAvailable) { Write-Warning " - Reason: Data Execution Prevention (DEP) is not available." }
        if (-not $virtInfo.HyperVRequirementSecondLevelAddressTranslation) { Write-Warning " - Reason: Second Level Address Translation (SLAT) is not available." }
        if (-not $virtInfo.HyperVRequirementVMMonitorModeExtensions) { Write-Warning " - Reason: VM Monitor Mode Extensions are not available." }
        return $false
    }
}

function Enable-WslAndInstallDebian {
    Write-Host "=== 1. Enabling WSL and Installing Debian ===" -ForegroundColor Cyan

    $features = @(
        "Microsoft-Windows-Subsystem-Linux",
        "VirtualMachinePlatform"
    )

    $restartNeeded = $false
    $isVirtSupported = Test-VirtualizationSupport

    # Always enable the base WSL feature
    $wslFeature = "Microsoft-Windows-Subsystem-Linux"
    if ((Get-WindowsOptionalFeature -Online -FeatureName $wslFeature).State -ne 'Enabled') {
        Write-Host "Enabling base feature: $wslFeature..."
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $wslFeature -NoRestart
        if ($result.RestartNeeded) { $restartNeeded = $true }
    } else {
        Write-Host "Base feature '$wslFeature' is already enabled."
    }

    # Only enable VirtualMachinePlatform if virtualization is supported
    if ($isVirtSupported) {
        $vmPlatformFeature = "VirtualMachinePlatform"
        if ((Get-WindowsOptionalFeature -Online -FeatureName $vmPlatformFeature).State -ne 'Enabled') {
            Write-Host "Enabling WSL2 feature: $vmPlatformFeature..."
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $vmPlatformFeature -NoRestart
            if ($result.RestartNeeded) { $restartNeeded = $true }
        }
    }

    if ($restartNeeded) {
        Write-Warning "A system restart is required to complete the installation of WSL2."
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

    if ($isVirtSupported) {
        wsl --set-default-version 2 | Out-Null
        Write-Host "[SUCCESS] WSL features configured for WSL2." -ForegroundColor Green
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

function Deploy-Wazuh {
    Write-Host "=== 2. Deploying Custom Wazuh Stack into Debian ===" -ForegroundColor Cyan

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

# --- Main Script Logic ---
Enable-WslAndInstallDebian
Deploy-Wazuh