# This script is used to install and configure the Azure Connected Machine Agent 
# 

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $AltDownloadLocation,

    [Parameter(Mandatory=$true)]
    [string] $remotePath = "\\dc-01.contoso.lcl\Software\Arc",

    [Parameter(Mandatory=$false)]
    [string] $logFile = "installationlog.txt",

    [Parameter(Mandatory=$false)]
    [string] $InstallationFolder = "$env:HOMEDRIVE\ArcDeployment",

    [Parameter(Mandatory=$false)]
    [string] $configFilename = "ArcConfig.json"
)

$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"

[string] $RegKey = "HKLM:\SOFTWARE\Microsoft\Azure Connected Machine Agent"

# create local installation folder if it doesn't exist
if (!(Test-Path $InstallationFolder) ) {
    [void](new-item -path $InstallationFolder -ItemType Directory )
} 

# create log file and overwrite if it already exists
$logpath = new-item -path $InstallationFolder -Name $logFile -ItemType File -Force

@"
Azure Arc-Enabled Servers Agent Deployment Group Policy Script
Time: $(Get-Date)
RemotePath: $remotePath
LocalPath: $localPath
RegKey: $RegKey
LogFile: $LogPath
InstallationFolder: $InstallationFolder
ConfigFileName: $configFileName
"@ >> $logPath 

try
{
    "Copying necessary items to $InstallationFolder" >> $logPath
    Copy-Item -Path "$remotePath\*" -Destination $InstallationFolder -Recurse -Verbose

    $agentData = Get-ItemProperty $RegKey -ErrorAction SilentlyContinue
    if ($agentData) {
        "Azure Connected Machine Agent version $($agentData.version) is already installed, proceeding to azcmagent connect" >> $logPath
    } else {
        # Agent is not installed, proceed with installation
        "Copying necessary items to $InstallationFolder" >> $logPath
        Copy-Item -Path "$remotePath\*" -Destination $InstallationFolder -Recurse -Verbose

        # Download the installation package
        "Started downloading the installation script" >> $logPath
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://aka.ms/azcmagent-windows" -TimeoutSec 30 -OutFile "$InstallationFolder\install_windows_azcmagent.ps1"
        "Finished downloading of the installation script" >> $logPath

        # Install the hybrid agent
        "Running the installation script" >> $logPath
        & "$InstallationFolder\install_windows_azcmagent.ps1"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install the hybrid agent: $LASTEXITCODE"
        }
        "Successfully ran the installation script" >> $logPath

        $agentData = Get-ItemProperty $RegKey -ErrorAction SilentlyContinue
        if (! $agentData) {
            throw "Could not read installation data from registry, a problem may have occurred during installation" 
            "Azure Connected Machine Agent version $($agentData.version) is already deployed, exiting without changes" >> $logPath
            exit
        }
        "Installation Complete" >> $logpath
    }

    & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --config "$InstallationFolder\$configFilename" >> $logpath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed during azcmagent connect: $LASTEXITCODE"
    }

    "Connect Succeeded" >> $logpath
    & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" show >> $logpath

} catch {
    "An error occurred during installation: $_" >> $logpath
}  