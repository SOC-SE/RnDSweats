Write-Host "--- Palo Alto Deployment Script ---" -ForegroundColor Cyan
$firewallIP  = Read-Host "Enter the Firewall IP address: "
$username    = Read-Host "Enter the account username: "
$internalZone = Read-Host "Enter the Internal zone name: "
$externalZone = Read-Host "Enter the External zone name: "
$customPublic = Read-Host "Enter the third octet of the public addresses: "
$commandFile = "comp-spec-win.txt"

(Get-Content $commandFile) | 
ForEach-Object { 
    $_ -replace 'CHANGEINTERNAL', $internalZone `
       -replace 'CHANGEEXTERNAL', $externalZone `
       -replace 'CHANGEOCTET', $customPublic
} |
Out-File $commandFile

if (-Not (Test-Path $commandFile)) {
    Write-Host "Error: Command file not found at $commandFile." -ForegroundColor Red
    exit
}

Write-Host "Connecting to $firewallIP..." -ForegroundColor Cyan
Write-Host "Applying configurations from $commandFile" -ForegroundColor Cyan

$sshCommand = "ssh -i -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa $username@$firewallIP < ""$commandFile"""

cmd.exe /c $sshCommand

Write-Host "Execution completed. Please check the output above for any Palo Alto CLI errors." -ForegroundColor Green