# <center>  Onboard to Azure Arc-enabled Servers Using Group Policy </center>

You can onboard your domain-joined Windows machines to Azure Arc-enabled servers at scale by using a Group Policy Object (GPO). This method requires that you have domain administrator privileges and access to group policy editor. You will also need a remote share to host the latest Azure Arc-enabled servers agent, configuration file, and the installation script.

The Group Policy creates a scheduled task on each computer in the organizational unit. The task will use the onboarding script (Scripts/AzureArcDeploymnetGPO.ps1) and configuration file from the network share and run the script. If successul, each computer in the OU will be connected as an Arc server in Azure using the specified subscription and resource group.

# Prerequisites

### Set up a Remote File Share

Prepare a remote share to host the Azure Connected Machine agent package for windows and the configuration file. Domain Computers need read access and the Domain Controller needs Change access. 

### Download the Install Script

Download the install script (Scripts/AzureArcDeploymentGPO.ps1) save it to the remote share.

### Define a Configuration File

The Azure Connected Machine agent uses a json configuration file to provide a consistent configuration experience and ease of at scale deployment. Copy the configuration Copy the ArcConfig.json file in the scripts folder to your remote share, and edit it with your onboarding information.

# Create a Group Policy Object

- Open the Group Policy managment console (GPMC). 
- Navigate to the location in your AD forest that contains the machines which you would like to join to Azure Arc-enabled servers. Then, right-click and select "Create a GPO in this domain, and Link it here." When prompted, assign a descriptive name to this GPO.
- Edit the GPO, navigate to the following location:
  ***Computer Configuration -> Preferences -> Control Panel Settings -> Scheduled Tasks***, right-click in the blank area, ***select New -> Scheduled Task (At least Windows 7)***

### Define the Scheduled Task

Open up the Scheduled Task wizard and configure the tabs as follows:

##### General tab 
    Action: Create
    Security options:
    - When running the task use the following  User account:  "NT AUTHORITY\System"
    - Select Run whether user is logged on or not.
    - Check Run with highest privileges
    Configure for : Choose Windows Vista or Window 2008.
<p  align = "center">
    <img src = "Pictures\ST-General.jpg">
</p>
  
#### Triggers Tab
    Click on the new button, in the new Trigger.
    Begin the task : select "On a schedule"
    Settings:
         - One time: choose the desired date and time.
         - Make sure to schedule the date and time at least 2 hours after the current time to make sure that the Group Policy update will be applied
    Advanced Settings:
         - Check Enabled 
<p align = "center"> 
  <img src= "Pictures\ST-Trigger.jpg">
</p>

#### Actions Tab
    Click on the new button , in the new Action window.
    - Action: select Start program
    - Settings 
        - Program/script: 
            - enter "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        - Add Arguments(optional): -ExecutionPolicy Bypass -command "& UNC path for the deployment powershell script" -remotePath <Path to your Remote Share>
        - Start in(optional): C:\
<p align = "center"> 
     <img src= "Pictures\ST-Actions.jpg">
</p>

# Apply the Group Policy Object 
    
On the Group Policy Management Console, you need to right-click on the desired Organizational Unit and select the option to link an existing GPO. Choose the Group Policy Object that you just created. After 10 or 20 minutes, the Group Policy Object will be replicated to the respective domain controllers. 
    
After you have successfully installed the agent and configure it to connect to Azure Arc-enabled servers, go to the Azure portal to verify that the servers in your Organizational Unit have successfully connected. View your machines in <a href = "https://aka.ms/hybridmachineportal">the Azure portal</a>.

# Troubleshooting
 - Group Policy Not Applying
   - Try forcing an update on the target machine with the following command in cmd: `gpupdate /force`
   - Try refreshing the OU in the Group Policy Management Error (right click on the OU -> Refresh)
   - Check Task Scheduler on the target machineto see if the task is being created and scheduled 
  
# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.