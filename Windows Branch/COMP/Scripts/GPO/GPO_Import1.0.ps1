#--------------------------------------------------------------
# GPO Import| AD Server
# Made by Logan Schultz
# Version | 1.0
#--------------------------------------------------------------

$params = @{
   BackupGpoName = "COMPGPO"
   Path = "C:\Github\RnDSweats-Development\Windows Branch/COMP/Scripts/GPO"
   TargetName = "NewCOMPGPO"
   CreateIfNeeded = $true
}
Import-GPO @params
