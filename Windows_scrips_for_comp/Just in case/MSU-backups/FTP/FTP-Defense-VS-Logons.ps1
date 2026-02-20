<# 
    ftp-hardening.ps1
    - Enable IIS FTP logon attempt restrictions (denyByFailure)
    - Limit max concurrent FTP connections to 30
#>

Import-Module WebAdministration

$siteName = "Default FTP Site"   # change if your FTP site name is different

Write-Host "Hardening FTP on site: $siteName"

# 1) Aggressive FTP logon attempt restrictions (denyByFailure)
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.ftpServer/security/authentication/denyByFailure" `
  -name "enabled" -value "True"

# Example: 3 bad logins in 1 minute -> banned for 1 hour
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.ftpServer/security/authentication/denyByFailure" `
  -name "maxFailure" -value 3

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.ftpServer/security/authentication/denyByFailure" `
  -name "failureInterval" -value "00:01:00"

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.ftpServer/security/authentication/denyByFailure" `
  -name "entryExpiration" -value "01:00:00"   # 1 hour ban

# 2) Limit concurrent FTP connections on this site to 30
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.applicationHost/sites/site[@name='$siteName']/ftpServer/connections" `
  -name "maxConnections" -value 30

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.applicationHost/sites/site[@name='$siteName']/ftpServer/connections" `
  -name "resetOnMaxConnections" -value "True"

Write-Host "FTP hardening complete: denyByFailure enabled, maxConnections=30."
