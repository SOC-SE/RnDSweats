<#
.SYNOPSIS
    Automates the deployment of a complete, customized Wazuh single-node stack
    on a Windows machine using Docker Desktop.

.DESCRIPTION
    This script orchestrates the entire setup process for a custom Wazuh environment
    running in Docker. It is designed to be run from the root of the 'RnDSweats'
    repository checkout on a system where Docker Desktop is already installed.

    The script performs the following actions:
    1. Checks that Docker and Docker Compose are available.
    2. Creates a dedicated directory for the Wazuh Docker deployment.
    3. Downloads the official Wazuh single-node `docker-compose.yml`.
    4. Starts the Wazuh stack using `docker-compose`.
    5. Waits for the Wazuh manager container to initialize.
    6. Copies the 'RnDSweats' repository into the running manager container.
    7. Executes the custom scripts ('fortressInstall.sh', 'setConfigs.sh') inside the container.
    8. Restarts the Wazuh manager service within the container to apply all changes.

.NOTES
    Author: Gemini Code Assist
    - This script MUST be run with Administrator privileges.
    - Docker Desktop (which includes Docker Compose) must be installed and running.
    - Assumes this script is located in `RnDSweats/WindowsDev` and run from the `RnDSweats` root.
#>

#Requires -RunAsAdministrator

function Test-DockerPrerequisites {
    Write-Host "=== 1. Checking for Docker Prerequisites ===" -ForegroundColor Cyan
    
    $dockerExists = Get-Command docker -ErrorAction SilentlyContinue
    $composeExists = Get-Command docker-compose -ErrorAction SilentlyContinue

    if (-not $dockerExists) {
        Write-Error "Docker command not found. Please install Docker Desktop and ensure it is running."
        exit 1
    }
    if (-not $composeExists) {
        Write-Error "Docker Compose command not found. Please ensure Docker Desktop is installed correctly."
        exit 1
    }

    Write-Host "[SUCCESS] Docker and Docker Compose are available." -ForegroundColor Green
}

function Deploy-WazuhInDocker {
    Write-Host "=== 2. Deploying Custom Wazuh Stack in Docker ===" -ForegroundColor Cyan

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
    $wslRepoPath = "/tmp/RnDSweats"

    Write-Host "Copying repository content into the '$containerName' container..."
    docker cp "$repoRoot" "${containerName}:$wslRepoPath"

    Write-Host "Executing custom scripts inside the container..."
    
    # Run the SOCFortress custom rules installation script
    Write-Host "--- Running fortressInstall.sh..."
    docker exec $containerName bash "${wslRepoPath}/Tools/Wazuh/fortressInstall.sh"

    # Run the group configuration script
    Write-Host "--- Running setConfigs.sh..."
    docker exec $containerName bash "${wslRepoPath}/Tools/Wazuh/Configs/setConfigs.sh"

    # Restart the manager to apply all new rules and configurations
    Write-Host "Restarting the wazuh-manager service inside the container..."
    docker exec $containerName systemctl restart wazuh-manager

    Write-Host "[SUCCESS] Custom Wazuh deployment in Docker is complete." -ForegroundColor Green
    Write-Host "You can access the Wazuh Dashboard at: https://localhost"
    Write-Host "Default credentials are user: admin, password: SecretPassword"
}

# --- Main Script Logic ---
Test-DockerPrerequisites
Deploy-WazuhInDocker

Write-Host "Script execution finished."