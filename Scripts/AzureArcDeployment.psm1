

function Get-ConnectionPointContainer {
    [CmdletBinding()]
    param()

    $systemcontainer = (Get-AdDomain).SystemsContainer
    Write-Verbose "Using system container $systemscontainer"

    return "CN=AzureArc,"+$systemcontainer
}

function Get-DisplayConnectionPoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        $adConnectionPoint
    )

    process {
        Write-Verbose "Processing $adConnectionPoint"
        Write-Verbose "SBI: $($adConnectionPoint.serviceBindingInformation)"
        $bindingParams = $adConnectionPoint.serviceBindingInformation | ConvertFrom-Json
        $output = [PSCustomObject]@{
            Name = $adConnectionPoint.Name
            Created = $adConnectionPoint.Created
            Modified = $adConnectionPoint.Modified
            DistinguishedName = $adConnectionPoint.DistinguishedName
            TenantId = $bindingParams."tenant-id"
            Location = $bindingParams."location"
            SubscriptionId = $bindingParams."subscription-id"
            ResourceGroup = $bindingParams."resource-group"
            ServicePrincipalId = $bindingParams."service-principal-id"
            ServicePrincipalSecret = $bindingParams."service-principal-secret"
        }
        $output
    }
}

function Get-ArcConnectionPoint {
    [CmdletBinding()]
    param()

    Write-Verbose "Getting Arc Connection Points"
    $container = Get-ConnectionPointContainer
    $serviceConnectionPoints = Get-ADObject -SearchBase $container -LDAPFilter "(objectClass=serviceConnectionPoint)" -Properties *
    if(!$serviceConnectionPoints) {
        Write-Warning "No Azure Arc Service Connection Points defined"
    } else {
        $serviceConnectionPoints | Get-DisplayConnectionPoint
    }
}

