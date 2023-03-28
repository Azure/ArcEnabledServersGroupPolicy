# Arc Deployment by GPO
Arc GPO Deployment project contains the necessary files to onboard Non Azure machines to Azure Arc automatically, using a GPO

More information can be found [here](https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-group-policy-service-principal-encryption)

## Content

- [DeployGPO.ps1](DeployGPO.ps1): PowerShell script to deploy the GPO in a certain AD domain
- [EnableAzureArc.ps1](EnableAzureArc.ps1): PowerShell script that has to be placed in the network share and will execute the onboarding process.
- [RenewSPSecretDPAPI.ps1](RenewSPSecretDPAPI.ps1): PowerShell script to renew the secret from the Service Principal used for the onboard of Azure Arc Servers.
- [ParseArcOnboardingPrerequisites.ps1](ParseArcOnboardingPrerequisites.ps1): PowerShell scripts that parses the information of the machines that didn't meet the onboard requirements.
- [ArcGPO](ArcGPO): Folder structure that contains the GPO settings to be imported in AD
- [ARMTemplates](ARMTemplates): Folder with Azure Function Template to monitor Azure Arc Agent version updates.
- [Workbooks](Workbooks): Folder with Azure Workbooks to monitor your Azure Arc onboarding Status and your Azure Arc Servers
- [ScheduledTask](ScheduledTask): Folder with a scheduled task that can, programmatically, upload on-prem XMLs report files to Azure Log Analytics

## Prerequisites

- Create a *Service Principal* and give it Azure Arc onbarding permissions, following this article: [Create a Service Principal for onboarding at scale](https://docs.microsoft.com/en-us/azure/azure-arc/servers/onboard-service-principal#create-a-service-principal-for-onboarding-at-scale)
  
- Register *Microsoft.HybridCompute*, *Microsoft.GuestConfiguration* and *Microsoft.HybridConnectivity* as resource providers in your subscription, following this article: [Register Resource Provider](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider)

- Create a *Network Share*,e.g. *AzureArcOnboard* that will be used for deployment and reporting files, with the following permissions:

  *Domain Controllers*, *Domain Computers* and *Domain Admins*: Change Permissions

 
- Copy the *'AzureConnectedMachineAgent.msi'* file to the shared folder.

    You can download it from https://aka.ms/AzureConnectedMachineAgent

## Installation

### Group Policy Deployment

- Copy the project structure to a local folder of a Domain Controller.

- Execute the deployment script *DeployGPO.ps1*, with the following syntax:
  
        .\DeployGPO.ps1 -DomainFQDN contoso.com -ReportServerFQDN Server.contoso.com -ArcRemoteShare AzureArcOnBoard -ServicePrincipalSecret $ServicePrincipalSecret 
       -ServicePrincipalClientId $ServicePrincipalClientId -SubscriptionId $SubscriptionId --ResourceGroup $ResourceGroup -Location $Location -TenantId $TenantId 
       [-AgentProxy $AgentProxy]

    Where:

    - *DomainFQDN* is the fully qualified domain name of the domain
    
    - *ReportServerFQDN* is the Fully Qualified Domain Name of the host where the network share resides.
    
    - *ArcRemoteShare* is the name of the network share you've created
    
    - *ServicePrincipalSecret* is the secret from the Service Principal created previously.
    
    - *ServicePrincipalClientId* is the client id from the Service Principal created previously

    - *SubscriptionId*, *ResourceGroup*, *Location*, *TenantId* corespond to where your Arc Servers are going to be onboarded

    - *AgentProxy* [optional] is the name of the proxy if used



