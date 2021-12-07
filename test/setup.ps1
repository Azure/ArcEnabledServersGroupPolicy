# Or another sublib subscription
Set-AzContext -SubscriptionId 07d2b1bb-d5e8-48e1-bc46-ead11d12c293
New-AzResourceGroup -Name edyoung -Location westus2

New-AzResourceGroupDeployment `
    -ResourceGroupName edyoung `
    -TemplateUri https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/application-workloads/active-directory/active-directory-new-domain/azuredeploy.json `
    -TemplateParameterFile .\parametersFile.json

