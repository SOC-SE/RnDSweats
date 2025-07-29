# Define variables
$WazuhManagerIP = "172.20.241.20"
$GatewayIP = "172.20.242.10"

# Download and install Wazuh Agent MSI silently (idempotent: check if installed)
$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi"
$InstallerPath = "$env:TEMP\wazuh-agent.msi"
if (-not (Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue)) {
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
    Start-Process msiexec.exe -ArgumentList "/i $InstallerPath /qn WAZUH_MANAGER=$WazuhManagerIP" -Wait
    Remove-Item $InstallerPath
}

# Start agent service (idempotent)
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

# Change default gateway on primary interface (idempotent: remove old, add new)
$Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty InterfaceAlias
Remove-NetRoute -InterfaceAlias $Interface -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
New-NetRoute -InterfaceAlias $Interface -DestinationPrefix "0.0.0.0/0" -NextHop $GatewayIP -Confirm:$false
