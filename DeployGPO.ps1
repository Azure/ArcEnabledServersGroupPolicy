# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -module ActiveDirectory
<#
.DESCRIPTION
    ##########################################################################################
    BE SURE TO PREPARE THE EnableAzureArc.ps1 onboarding script BEFORE LAUNCHING THIS SCRIPT!!
    ##########################################################################################

   This script needs to be executed in a Domain Controller and makes the following actions:
   
    - Deploys the Azure Arc Servers Onboarding GPO in the local domain as 
      '[MSFT] Azure Arc Servers Onboarding<Timestamp>'
      
    - Copies the EnableAzureArc.ps1 onboarding script to the network Share

.PARAMETER DomainFQDN
   FQDN of the Domain to Deploy e.g. contoso.com

.PARAMETER ReportServerFQDN
   FQDN of the Server that will act as report Server (and source files)

.PARAMETER spsecret
   Service Principal's secret
   Use this link to create a new one:
   https://docs.microsoft.com/en-us/azure/azure-arc/servers/onboard-service-principal#create-a-service-principal-for-onboarding-at-scale
   
.PARAMETER ArcRemoteShare
   Remote share that holds deployment source files and reporting files

.PARAMETER AgentProxy
   proxy address used by the Agent

.EXAMPLE
   This example deploys the GPO to the contoso.com domain and copies the onboarding script EnableAzureArc.ps1
   to the remote share AzureArcOnBoard in the Server.contoso.com server

   .\DeployGPO.ps1 -DomainFQDN contoso.com -ReportServerFQDN Server.contoso.com -ArcRemoteShare AzureArcOnBoard -Spsecret $spsecret [-AgentProxy $AgentProxy]

#>

Param (
    [Parameter(Mandatory = $True)]
    [System.String]$DomainFQDN,
    [Parameter(Mandatory = $True)]
    [System.String]$ReportServerFQDN, # "server.contoso.com"
    [Parameter(Mandatory = $True)]
    [System.String]$Spsecret,
    [System.String]$ArcRemoteShare = "AzureArcOnboard",
    [System.String]$AgentProxy,
    [switch]$AssessOnly
)

$ErrorActionPreference = "Stop"

$GPOName = "[MSFT] Azure Arc Servers Onboarding"


#Create the remote folders AzureArcDeploy & AzureArcLogging

$FolderRemotepath = "\\$ReportServerFQDN\$ArcRemoteShare"

if (-not (Test-Path $FolderRemotepath -ErrorAction SilentlyContinue)) {
    throw "The Path $FolderRemotepath does't exist, please creat it before running this script!!"
}
else {
    Write-Host "Remote path  $FolderRemotepath found!" -ForegroundColor Green
}

Write-Host "Creating remote folder's structure..." -ForegroundColor Green

try {
    New-Item -ItemType Directory -Path "$FolderRemotepath\AzureArcDeploy" -Force -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path "$FolderRemotepath\AzureArcLogging" -Force -ErrorAction Stop | Out-Null
}
catch { Write-Host "Could not create remote folders in path $FolderRemotepath`n$(($_.Exception).Message)" -ForegroundColor Red ; exit }

$AzureArcDeployPath = "$FolderRemotepath\AzureArcDeploy"
$AzureArcLoggingPath = "$FolderRemotepath\AzureArcLogging"


#region assign appropiate permissions to the folders

Write-Host "Assigning appropriate permissions..." -ForegroundColor Green

#Remove inheritance

$Acl = Get-ACL -Path $AzureArcDeployPath
$Acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $AzureArcDeployPath -AclObject $Acl

$Acl = Get-ACL -Path $AzureArcLoggingPath
$Acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $AzureArcLoggingPath -AclObject $Acl



#Add Access to Domain Computers and Domain Controllers
$DomainNetbios = (Get-ADDomain $DomainFQDN).NetBIOSName
$DomainComputersSID = (Get-ADDomain).DomainSID.Value + '-515'
$DomainComputersName = (Get-ADGroup -Filter "SID -eq `'$DomainComputersSID`'").Name
$DomainControllersSID = (Get-ADDomain).DomainSID.Value + '-516'
$DomainControllersName = (Get-ADGroup -Filter "SID -eq `'$DomainControllersSID`'").Name


$identity = "$DomainNetbios\$DomainComputersName"
$identity2 = "$DomainNetbios\$DomainControllersName"


#Deploy Path
$NewAcl = Get-ACL -Path $AzureArcDeployPath
$fileSystemAccessRules = 
@(   
    [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'ReadandExecute', "ContainerInherit,ObjectInherit", 'None', 'Allow')
    [System.Security.AccessControl.FileSystemAccessRule]::new($identity2, 'ReadandExecute', "ContainerInherit,ObjectInherit", 'None', 'Allow')  
)
foreach ($fileSystemAccessRule in $fileSystemAccessRules) {

    $NewAcl.SetAccessRule($fileSystemAccessRule)
    Set-Acl -Path $AzureArcDeployPath -AclObject $NewAcl
}


#Logging Path
$NewAcl = Get-ACL -Path $AzureArcLoggingPath
$fileSystemAccessRules = 
@(   
    [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'ReadandExecute,Write,Modify', "ContainerInherit,ObjectInherit", 'None', 'Allow')
    [System.Security.AccessControl.FileSystemAccessRule]::new($identity2, 'ReadandExecute,Write,Modify', "ContainerInherit,ObjectInherit", 'None', 'Allow')  
)
foreach ($fileSystemAccessRule in $fileSystemAccessRules) {
    $NewAcl.SetAccessRule($fileSystemAccessRule)
    Set-Acl -Path $AzureArcLoggingPath -AclObject $NewAcl
}

#endregion



#region Replacing Custom Data in the scheduled task

#Replacing the data in the scheduled task

$BackupPath = "$PSScriptRoot\ArcGPO"
$Backupid = ((Get-ChildItem -Path $BackupPath | Sort-Object -Property LastWriteTime -Descending) | Select-Object -First 1 -ExpandProperty Name) -replace "{" -replace "}"
$ScheduledTaskfile = "$BackupPath\{$Backupid}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"

Write-Host "`nReplacing the data the scheduled task..." -ForegroundColor Green

try {
    $xmlcontent = Get-Content -Path $ScheduledTaskfile -ErrorAction Stop
    $xmlcontent -replace "{ReportServerFQDN}", $ReportServerFQDN | Out-File $ScheduledTaskfile -Encoding utf8 -Force -ErrorAction Stop
    Write-Host "Report Server FQDN $ReportServerFQDN was successfully set in the scheduled task" -ForegroundColor Green

    $xmlcontent = Get-Content -Path $ScheduledTaskfile -ErrorAction Stop
    $xmlcontent -replace "{ArcRemoteShare}", "$ArcRemoteShare" | Out-File $ScheduledTaskfile -Encoding utf8 -Force -ErrorAction Stop
    Write-Host "Arc Remote share $ArcRemoteShare was successfully set in the scheduled task..." -ForegroundColor Green

    if ($PSBoundParameters.ContainsKey('AssessOnly')) {
        $xmlcontent = Get-Content -Path $ScheduledTaskfile -ErrorAction Stop
        $xmlcontent -replace "ArcRemoteShare $ArcRemoteShare", "ArcRemoteShare $ArcRemoteShare -AssessOnly" | Out-File $ScheduledTaskfile -Encoding utf8 -Force -ErrorAction Stop
        Write-Host "AssessMode was successfully set in the scheduled task..." -ForegroundColor Green
    }

}
catch { Write-Host "Could not modify Scheduled task:`n$(($_.Exception).Message)" -ForegroundColor Red ; exit }


#Add proxy server information if neccessary

if ($PSBoundParameters.ContainsKey('AgentProxy')) {
    Write-Host "`nProxy was selected. Adding proxy $AgentProxy to the scheduled task ..." -ForegroundColor Green

    try {
        $xmlcontent = Get-Content -Path $ScheduledTaskfile -ErrorAction Stop
        ($xmlcontent -replace "EnableAzureArc.ps1 -ArcRemoteShare", "EnableAzureArc.ps1 -ReportServerFQDN $ReportServerFQDN -AgentProxy $AgentProxy -ArcRemoteShare") | Out-File $ScheduledTaskfile -Encoding utf8 -Force -ErrorAction Stop
        Write-Host "Proxy information was successfully added to the scheduled task" -ForegroundColor Green
    }
    catch { Write-Host "Could not add Proxy Information:`n$(($_.Exception).Message)" -ForegroundColor Red ; exit }
    
} 
else {
    Write-Host "`nAdding ReportServerFQDN $ReportServerFQDN to the scheduled task ..." -ForegroundColor Green

    try {
        $xmlcontent = Get-Content -Path $ScheduledTaskfile -ErrorAction Stop
        ($xmlcontent -replace "EnableAzureArc.ps1 -ArcRemoteShare", "EnableAzureArc.ps1 -ReportServerFQDN $ReportServerFQDN -ArcRemoteShare") | Out-File $ScheduledTaskfile -Encoding utf8 -Force -ErrorAction Stop
        Write-Host "ReportServerFQDN was successfully added to the scheduled task" -ForegroundColor Green
    }
    catch { Write-Host "Could not add ReportServerFQDN:`n$(($_.Exception).Message)" -ForegroundColor Red ; exit }
}

#endregion

#Creating the new GPO
Write-Host "`nCreating the new GPO..." -ForegroundColor Green

try {
    $GPONamewithTimestamp = "$GPOName$(Get-Date -Format yyyyMMddhhmmss)"
    New-GPO -Name $GPONamewithTimestamp -ErrorAction Stop
    Write-Host "GPO `'$GPONamewithTimestamp`' was successfully created in Domain $DomainFQDN" -ForegroundColor Green
}
catch { Write-Host "The Group Policy could not be created:`n$(($_.Exception).Message)" -ForegroundColor Red ; break }


# Encrypting the SPSecret to be decrypted only by the Domain Controllers and the Domain Computers security groups

$DomainComputersSID = "SID=" + $DomainComputersSID
$DomainControllersSID = "SID=" + $DomainControllersSID
$descriptor = @($DomainComputersSID, $DomainControllersSID) -join " OR "

Import-Module $PSScriptRoot\AzureArcDeployment.psm1
$encryptedSecret = [DpapiNgUtil]::ProtectBase64($descriptor, $spsecret)

#Copying Script to Source files Subfolder path
Write-Host "`nCopying Script EnableAzureArc.ps1 to path $AzureArcDeployPath ..." -ForegroundColor Green

try {
    if (Test-Path "$AzureArcDeployPath\EnableAzureArc.ps1" -ErrorAction SilentlyContinue) {
        Write-Host "File `'$AzureArcDeployPath\EnableAzureArc.ps1`' already exists." -ForegroundColor Red; throw
    }
    else {
        Copy-Item -Path "$PSScriptRoot\EnableAzureArc.ps1" -Destination $AzureArcDeployPath -ErrorAction Stop
        Write-Host "Onboarding script `'EnableAzureArc.ps1`' successfully copied to $AzureArcDeployPath" -ForegroundColor Green
    }

    if (Test-Path "$AzureArcDeployPath\AzureArcDeployment.psm1" -ErrorAction SilentlyContinue) {
        Write-Host "File `'$AzureArcDeployPath\AzureArcDeployment.psm1`' already exists." -ForegroundColor Red; throw
    }
    else {
        Copy-Item -Path "$PSScriptRoot\AzureArcDeployment.psm1" -Destination $AzureArcDeployPath -ErrorAction Stop
        Write-Host "Onboarding script `'AzureArcDeployment.psm1`' successfully copied to $AzureArcDeployPath" -ForegroundColor Green
    }

    $encryptedSecret | Out-File -FilePath (Join-Path -Path $AzureArcDeployPath -ChildPath "encryptedServicePrincipalSecret") -Force

}
catch { Write-Host "Onboarding script could not be copied:`n$(($_.Exception).Message)" -ForegroundColor Red ; break }


#Import the setting from the backup
Write-Host "`nImport the setting from the backup..." -ForegroundColor Green

try {
    Import-GPO -Path $BackupPath -TargetName $GPONamewithTimestamp -BackupId $Backupid -ErrorAction Stop
    Write-Host "GPO Setting were successfully imported.`nOpen GPO Management Console and Check for '$GPONamewithTimestamp`' Group policy" -ForegroundColor Green
    Write-Host "`nBe sure to copy the `'AzureConnectedMachineAgent.msi`' file to the $AzureArcDeployPath folder!!" -ForegroundColor Yellow
    Write-Host "You can download it from `'https://aka.ms/AzureConnectedMachineAgent`'" -ForegroundColor Green
    gpmc.msc
}
catch { Write-Host "The Group Policy setting could not be imported:`n$(($_.Exception).Message)" -ForegroundColor Red ; break }