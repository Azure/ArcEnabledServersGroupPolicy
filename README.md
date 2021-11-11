# <center>  Deploy and Configure  Azure Arc for Servers Using GPO </center>

<br> </br>

You can enable Azure Arc enabled servers for domain joined windows machines in your enviroment using Group Policy Object (GPO).

This method requires that you have domain administrator privilege and access to group policy editor, you also need a remote share  to host the latest Azure Arc enabled servers agent version, configuration file and the instaltion script.

# Prerequisites

### Distributed location

Prepare a remote share to host the Azure connected Machine agent package for windows and the configuration file, at least you need read only access

### Download the agent

Download [Windows agent Windows Installer package](https://aka.ms/AzureConnectedMachineAgent) from the Microsoft Download Center and save it to the remote share.

### Creating  Configuration file

The Azure connected Machine agent uses a Json configuration files to provide a consistence configuration experience and eas the at scale deployment, the file structure is looks like this 
```
    {
        "tenant-id": "YOUR AZURE TENANTID",
        "subscription-id": "YOUR AZURE SUBSCRIPTION ID",
        "resource-group": "RESOURCE GROUP NAME",
        "location": "REGION",
        "service-principal-id":"SPN ID",
        "service-principal-secret": "SPN Secret"
    }
```

Copy the above the content in a file and save in a the remote share as a json file. 

### Create a Group Policy Object

- Open the Group Policy managment console (GPMC), navigate to the location in your AD forst that contains the VMs which you would like to join to Azure Arc, then eight-click and select "Create a GPO in this domain, and Link it here." When prompted, assign a descriptive name to this GPO:
- Edit the GPO, navigate to the following location:
  ***Computer Configuration -> Preferences -> Control Panel Settings -> Scheduled Tasks***, right-click in the blank area, ***select New -> Schedueled Task (At least Windows 7)***

### Creating the Scheduel Task
open the schedueled task and configure as following: 
##### General tab 
    Action: Create
    Security options:
    - When running the task use the following  User account:  "NT AUTHORITY\System"
    - Select Run whether user is logged on or not.
    - Check Run with highest priviledges
    Configure for : Choose Windows Vista or Window 2008.
<p  align = "center">
    <img src = "Pictures\ST-General.jpg">
</p>
  
#### Triggers Tab
    Click on the new button, in the new Trigger 
    Begin the task : select "On a schedule"
    Settings:
         - One time: choose the desired date and time.
         - Make sure to scheduel the date and   time after after the GPO resfresh interval for computers, By default, computer Group Policy is updated in the background every 90 minutes, with a random offset of 0 to 30 minutes
    Advanced Settings:
         - Check Enabled 
<p align = "center"> 
  <img src= "Pictures\ST-Trigger.jpg">
</p>

#### Actions Tab
    click on the new button , in the new Action window 
    - Action: select Start program
    - Settings 
        - Program/script: 
            - enter "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        - Add Arguments(optional): -ExecutionPolicy Bypass -command "& UNC path for the deployment powershell script "
        - the following is a simple example of how to install and onboard the server to Azure using the config file you have created in the previous step 
<br>

    [string] $remotePath = "\\dc-01.contoso.lcl\Software\Arc"
    [string] $localPath = "$env:HOMEDRIVE\ArcDeployment"
    [string] $RegKey = "HKLM\SOFTWARE\Microsoft\Azure Connected Machine Agent"
    [string] $logFile = "installationlog.txt"
    [string] $InstaltionFolder = "ArcDeployment"
    [string] $configFilename = "ArcConfig.json"

    if (!(Test-Path $localPath) ) {
        $BitsDirectory = new-item -path C:\ -Name $InstaltionFolder -ItemType Directory 
        $logpath = new-item -path $BitsDirectory -Name $logFile -ItemType File
    }
    else{
    $BitsDirectory = "C:\ArcDeployment"
    }
    function Deploy-Agent {
        [bool] $isDeployed = Test-Path $RegKey
        if ($isDeployed) {
            $logMessage = "Azure Arc Serverenabled agent is deployed , exit process"
            $logMessage >> $logpath
            exit
        }
        else { 
            Copy-Item -Path "$remotePath\*" -Destination $BitsDirectory -Recurse -Verbose
            $exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", "$BitsDirectory\AzureConnectedMachineAgent.msi" , "/l*v", "$BitsDirectory\$logFile", "/qn") -Wait -Passthru).ExitCode
            
            if($exitCode -eq 0){
           Start-Sleep -Seconds 120
           $x=   & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --config "$BitsDirectory\$configFilename"
                $msg >> $logpath 
            }
            else {
                $message = (net helpmsg $exitCode)
                $message >> $logpath 
            }
    
        }
    }
</br>
        - Start in(optional): C:\
<p align = "center"> 
     <img src= "Pictures\ST-Actions.jpg">
</p

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
