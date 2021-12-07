# new AD template deployment doesn't have NSGs, that needs fixing

# Creating SCP with PowerShell

New-ADObject -Name "AzureArc" -Type "container" -Path "CN=system,DC=contoso,DC=com"
New-ADObject -Name "AzureArc" -Type "serviceConnectionPoint" -Path "CN=AzureArc,CN=system,DC=contoso,DC=com" -

# creating SP
$sp = New-AzADServicePrincipal -DisplayName "Arc-for-servers-hrp-sublib-006" -Role "Azure Connected Machine Onboarding" -Scope /subscriptions/07d2b1bb-d5e8-48e1-bc46-ead11d12c293

# get password

$credential = New-Object pscredential -ArgumentList "temp", $sp.Secret
$p = $credential.GetNetworkCredential().password

# get SID of domain computers group
$sid = (get-adgroup 'domain computers').sid.Value

# get encrypted password
.\dpapitool.exe encrypt "SID=$sid" $p
$encrypted = (.\dpapitool.exe encrypt "SID=$sid" $p | findstr /v Hello) 

# construct params
$params=@{"subscription-id"="07d2b1bb-d5e8-48e1-bc46-ead11d12c293";"tenant-id"="72f988bf-86f1-41af-91ab-2d7cd011db47";"resource-group"="edyoung";location="westus2";"service-principal-id"="e5bc350f-2a42-4b6d-bf48-ef91e3442edc";"service-principal-secret"=$encrypted}

# construct SCP with params
New-ADObject -Name "AzureArc" -Type "serviceConnectionPoint" -Path "CN=AzureArc,CN=system,DC=contoso,DC=com" -OtherAttributes @{
    keywords="AzureArcEnabledServers";
    serviceBindingInformation=($params | ConvertTo-Json);
    serviceClassName="AzureArcEnabledServers"
}


# Retrieve SCP
$scpnew = Get-ADObject -SearchBase "CN=AzureArc,CN=system,DC=contoso,DC=com" -LDAPFilter "(objectClass=serviceConnectionPoint)" -Properties *

# get binding info
$bindingprops = ($scpnew.serviceBindingInformation | ConvertFrom-Json)

decrypt password

.\dpapitool decrypt $bindingprops.'service-principal-secret'

# We can't assume that Az module is installed on DC but there are quite a lot of extra checks we could do if it is
# - check that password works, not expired
# - check that service principal exists
# - check that subscription etc works

# We could split things - have one script/command to be run from DC to create the SCP container and set ACL on that to be more permissive. 
# Then creation of SCPs can be done by a member of the delegated group using commands from some other server. 


