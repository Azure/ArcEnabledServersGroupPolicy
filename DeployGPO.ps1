# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -module ActiveDirectory
<#
.DESCRIPTION
   This script needs to be executed in a Domain Controller and makes the following actions:
   
    - Deploys the Azure Arc Servers Onboarding GPO in the local domain as 
      '[MSFT] Azure Arc Servers Onboarding<Timestamp>'
      
    - Copies the EnableAzureArc.ps1 onboarding script to the network Share

.PARAMETER DomainFQDN
   FQDN of the Domain to Deploy e.g. contoso.com

.PARAMETER ReportServerFQDN
   FQDN of the Server that will act as report Server (and source files)

.PARAMETER ServicePrincipalSecret
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

   .\DeployGPO.ps1 -DomainFQDN contoso.com -ReportServerFQDN Server.contoso.com -ArcRemoteShare AzureArcOnBoard -ServicePrincipalSecret $ServicePrincipalSecret 
       -ServicePrincipalClientId $ServicePrincipalClientId -SubscriptionId $SubscriptionId --ResourceGroup $ResourceGroup -Location $Location -TenantId $TenantId 
       [-AgentProxy $AgentProxy]

#>

Param (
    [Parameter(Mandatory = $True)]
    [System.String]$DomainFQDN,
    [Parameter(Mandatory = $True)]
    [System.String]$ReportServerFQDN, # "server.contoso.com"
    
    [Parameter(Mandatory = $True)]
    [System.String]$ServicePrincipalClientId,
    [Parameter(Mandatory = $True)]
    [System.String]$ServicePrincipalSecret,
    
    [Parameter(Mandatory = $True)]
    [System.String]$SubscriptionId,
    [Parameter(Mandatory = $True)]
    [System.String]$ResourceGroup,
    [Parameter(Mandatory = $True)]
    [System.String]$Location,

    [Parameter(Mandatory = $True)]
    [System.String]$TenantId,

    [Parameter(Mandatory = $True)]
    [System.String]$ArcRemoteShare,

    [Parameter(Mandatory = $False)]
    [System.String]$AgentProxy,

    [Parameter(Mandatory = $False)]
    [switch]$UseEncryption = $True,
    
    [System.String]$GatewayId,
    
    [Parameter(Mandatory = $False)]
    [System.String]$PrivateLinkScopeId,

    [Hashtable]$Tags,

    [switch]$AssessOnly
)

if(-not $UseEncryption){
    $prompt = @"
UseEncryption=false specified. Please be aware that the secret will only be encoded in base64
and the secret will be easily decodable to anyone with read permissions to the remote share.  
Do you wish to continue with base64 encoding? (y/n)
"@
    $proceed = Read-Host $prompt
    if($proceed -ne "y"){
        Write-Host "Exiting DeployGPO.ps1"
        return
    }
    Write-Host "Proceeding with base64 encoding"
}

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

Write-Host "`nAdding ReportServerFQDN $ReportServerFQDN to the scheduled task ..." -ForegroundColor Green

try {
    $xmlcontent = Get-Content -Path $ScheduledTaskfile -ErrorAction Stop
    ($xmlcontent -replace "EnableAzureArc.ps1 -ArcRemoteShare", "EnableAzureArc.ps1 -ReportServerFQDN $ReportServerFQDN -ArcRemoteShare") | Out-File $ScheduledTaskfile -Encoding utf8 -Force -ErrorAction Stop
    Write-Host "ReportServerFQDN was successfully added to the scheduled task" -ForegroundColor Green
}
catch { Write-Host "Could not add ReportServerFQDN:`n$(($_.Exception).Message)" -ForegroundColor Red ; exit }

#endregion

#Creating the new GPO
Write-Host "`nCreating the new GPO..." -ForegroundColor Green

try {
    $GPONamewithTimestamp = "$GPOName$(Get-Date -Format yyyyMMddhhmmss)"
    New-GPO -Name $GPONamewithTimestamp -ErrorAction Stop
    Write-Host "GPO `'$GPONamewithTimestamp`' was successfully created in Domain $DomainFQDN" -ForegroundColor Green
}
catch { Write-Host "The Group Policy could not be created:`n$(($_.Exception).Message)" -ForegroundColor Red ; break }


# Encrypting the ServicePrincipalSecret to be decrypted only by the Domain Controllers and the Domain Computers security groups

$encryptedSecret = [Convert]::ToBase64String([char[]]"$ServicePrincipalSecret")
if ($UseEncryption){
    $DomainComputersSID = "SID=" + $DomainComputersSID
    $DomainControllersSID = "SID=" + $DomainControllersSID
    $descriptor = @($DomainComputersSID, $DomainControllersSID) -join " OR "

    Import-Module $PSScriptRoot\AzureArcDeployment.psm1
    $encryptedSecret = [DpapiNgUtil]::ProtectBase64($descriptor, $ServicePrincipalSecret)
}

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

    if (Test-Path "$AzureArcDeployPath\AzureConnectedMachineAgent.msi" -ErrorAction SilentlyContinue) {
        Write-Host "File `'$AzureArcDeployPath\AzureConnectedMachineAgent.msi`' already exists." -ForegroundColor Red; throw
    }
    else {
        Copy-Item -Path "$FolderRemotepath\AzureConnectedMachineAgent.msi" -Destination $AzureArcDeployPath -ErrorAction Stop
        Write-Host "Install file `'AzureConnectedMachineAgent.msi`' successfully copied to $AzureArcDeployPath" -ForegroundColor Green
    }

    $infoTable = @{
        "ServicePrincipalClientId" = "$ServicePrincipalClientId"
        "SubscriptionId" = "$SubscriptionId"
        "ResourceGroup" = "$ResourceGroup"
        "Location" = "$Location"
        "TenantId" = "$TenantId"
        "PrivateLinkScopeId" = "$PrivateLinkScopeId"
        "Tags" = $tags
        "UseEncryption" = "$UseEncryption"
        "AgentProxy"="$AgentProxy"
        "GatewayId"="$GatewayId"
    }
    $infoTableJSON = $infoTable | ConvertTo-Json -Compress
    
    if (Test-Path "$AzureArcDeployPath\ArcInfo.json" -ErrorAction SilentlyContinue) {
        Write-Host "File `'$AzureArcDeployPath\ArcInfo.json`' already exists." -ForegroundColor Red; throw
    }
    else {
        $infoTableJSON | Out-File -FilePath "$AzureArcDeployPath\ArcInfo.json"
        Write-Host "JSON file with onboarding info `'ArcInfo.json`' successfully copied to $AzureArcDeployPath" -ForegroundColor Green
    }

    $encryptedSecret | Out-File -FilePath (Join-Path -Path $AzureArcDeployPath -ChildPath "encryptedServicePrincipalSecret") -Force

}
catch { Write-Host "Onboarding script could not be copied:`n$(($_.Exception).Message)" -ForegroundColor Red ; break }


#Import the setting from the backup
Write-Host "`nImport the setting from the backup..." -ForegroundColor Green

try {
    Import-GPO -Path $BackupPath -TargetName $GPONamewithTimestamp -BackupId $Backupid -ErrorAction Stop
    Write-Host "GPO Setting were successfully imported.`nOpen GPO Management Console and Check for '$GPONamewithTimestamp`' Group policy" -ForegroundColor Green
    gpmc.msc
}
catch { Write-Host "The Group Policy setting could not be imported:`n$(($_.Exception).Message)" -ForegroundColor Red ; break }
