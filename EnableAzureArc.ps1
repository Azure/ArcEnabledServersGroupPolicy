# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    This Script is meant to be in a network share and onboards a server in Azure Arc
    using a Service Principal:
    https://docs.microsoft.com/en-us/azure/azure-arc/servers/onboard-service-principal#create-a-service-principal-for-onboarding-at-scale
   
    It makes the following validation checks before the onboarding:

        - Checks if the machine is an Azure VM or a Non Azure Machine
        - Checks Framework Version
        - Checks PowerShell Version
 
    If the server doesn't pass the requirements, all the information from the server: OS, Framework version,
    PowerShell version, VM type ... is stored in a network share for further analisys.

    If the server pass the requirements, the script checks if the Azure Hybrid Instance Metadata Service is already installed

        If not, the script:

        - Install the Connected Machine agent on the machine
        - Connects the server to Azure Arc using a Service Principal
        - Tags Azure Arc server with a given Tag
        - Any Connection error is logged and the Agent code get: https://docs.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard#agent-error-codes


        In positive case, the script:

        - Checks azcmagent.exe version and updates the agent if a new version is found in the network folder
        - Checks its connection status
        - In case the server is disconnected it logs the last errors from the azcmagent.exe Agent on the shared folder


.PARAMETER ReportServerFQDN
   FQDN of the Server that will act as report Server (and source files)

.PARAMETER AssessOnly
   Switch parameter that makes script work in Assess mode.
   No machines will be onboarded in Azure Arc.
   Machines will only report if their prerequesites are met or not to the report share

.EXAMPLE
   This example onboards machines in Azure Arc 
   
   .\EnableAzureArc.ps1 -ArcRemoteShare AzureArcOnBoard 

.EXAMPLE
   This example assesses machines Azure Arc prerequisites and sends the info to the report share

   .\EnableAzureArc.ps1 -ArcRemoteShare AzureArcOnBoard -AssessOnly

#>

Param (
    [Parameter(Mandatory = $true)]
    [System.String]$ArcRemoteShare,
    [Parameter(Mandatory = $true)]
    [System.String]$ReportServerFQDN,
    [switch]$AssessOnly
)

#Calculate Logging path
$LoggingNetworkPath = "$((Join-Path -Path "\\$ReportServerFQDN" -ChildPath $ArcRemoteShare) -replace "\\$")" + "\AzureArcLogging"

#Calculate network full path
$SourceFilesFullPath = "$((Join-Path -Path "\\$ReportServerFQDN" -ChildPath $ArcRemoteShare) -replace "\\$")" + "\AzureArcDeploy"

$arcInfo = Get-Content (Join-Path $SourceFilesFullPath "ArcInfo.json") | ConvertFrom-Json

###########################################################################################################
# Add the service principal application ID and more data here:
$servicePrincipalClientId = $arcInfo.ServicePrincipalClientId
$tenantid = $arcInfo.TenantId
$subscriptionid = $arcInfo.SubscriptionId
$ResourceGroup = $arcInfo.ResourceGroup
$location = $arcInfo.Location
$PrivateLinkScopeId = $arcInfo.PrivateLinkScopeId
$AgentProxy = $arcInfo.AgentProxy
$GatewayId = $arcInfo.GatewayId

$tags = @{ # Tags to be added to the Arc servers
    DeployedBy  = "GPO"
}

if($arcInfo.Tags){
    $arcInfo.Tags.psobject.properties | Foreach { $tags[$_.Name] = $_.Value }
}

$workfolder = "$env:SystemDrive\temp"
$logpath = "$workfolder\AzureArcOnboarding.log" #Local log file
###########################################################################################################

#region Functions and classes Definition

Function Get-ArcAgentstatus {
    Param (
        [Switch]$loglocally,

        [ValidateSet("info", "error")]
        [System.String[]]$logtype
    )

    $agentstatus = (& "$($env:ProgramW6432)\AzureConnectedMachineAgent\azcmagent.exe" show -j) | ConvertFrom-Json

    if ($loglocally) {
        # Logs the status in the AzureArcAgentOnboarding.log

        switch ($logtype) {
            "info" {
                $agentstatus | Get-Member -MemberType NoteProperty -Name "*HeartBeat" | ForEach-Object {
                    Write-Log -msg "$($_.Name) : $($agentstatus.$($_.Name))" -msgtype INFO
                }
            }
            "error" {
                $agentstatus | Get-Member -MemberType NoteProperty -Name "*Error*" | ForEach-Object {
                    Write-Log -msg "$($_.Name) : $($agentstatus.$($_.Name))" -msgtype ERROR
                }
            }
        }
    }


    $agentstatushash = [ordered]@{}
    $agentstatus.psobject.properties | Sort-Object -Property Name | ForEach-Object { $agentstatushash[$_.Name] = $_.Value } # Converts to Hashtable
    return $agentstatushash
}
Function Get-ArcAgentErrorLogs {
    [cmdletbinding()]
    Param(
        [datetime]$since
    )

    $script:azcmagentErrors = Get-Content "$env:Programdata\AzureConnectedMachineAgent\Log\azcmagent.log" | Select-String "level=fatal" | Where-Object { [datetime](($_ -split "\s")[0] -replace "time=" -replace '"') -gt $since }
    $HimdsErrors = Get-Content "$env:Programdata\AzureConnectedMachineAgent\Log\himds.log" | Select-String "error" |
    Where-Object { [datetime](($_ -split "\s")[0] -replace "time=" -replace '"') -gt $since }
    foreach ($azcmagentError in $script:azcmagentErrors) {
        Write-Log -msg $azcmagentError -msgtype ERROR
    }
    foreach ($HimdsError in $HimdsErrors) {
        Write-Log -msg $HimdsError -msgtype ERROR
    }


}
Function Get-EmbeddedAuthenticodeCertificates {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $resolvedPath = Resolve-Path -LiteralPath $FilePath -ErrorAction Stop | Select-Object -ExpandProperty Path

    # Extract certificates embedded in the file's Authenticode PKCS#7 signature (leaf + intermediates).
    # X509Chain.Build() only receives the leaf cert and must discover intermediates from the local
    # certificate store or via AIA download. On locked-down networks where intermediates aren't cached
    # and AIA endpoints are unreachable, Build() fails. Since the MSI's Authenticode signature already
    # embeds these intermediates, we extract them here so they can be supplied via ExtraStore.
    $TypeName = 'AuthenticodeCertExtractor'
    if (-not ([System.Management.Automation.PSTypeName]$TypeName).Type) {
        Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public static class AuthenticodeCertExtractor {
    private const int CERT_QUERY_OBJECT_FILE                     = 0x1;
    private const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400;
    private const int CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED      = 10;
    private const int CERT_QUERY_FORMAT_FLAG_ALL                 = 0xE;

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptQueryObject(
        int dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)] string pvObject,
        int dwExpectedContentTypeFlags,
        int dwExpectedFormatTypeFlags,
        int dwFlags,
        out int pdwMsgAndCertEncodingType,
        out int pdwContentType,
        out int pdwFormatType,
        out IntPtr phCertStore,
        out IntPtr phMsg,
        out IntPtr ppvContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertCloseStore(IntPtr hCertStore, int dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgClose(IntPtr hCryptMsg);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

    public static X509Certificate2Collection Extract(string filePath) {
        IntPtr hStore, hMsg, hCtx;
        int encType, contentType, formatType;

        if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, filePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL, 0,
            out encType, out contentType, out formatType,
            out hStore, out hMsg, out hCtx)) {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, String.Format(
                "CryptQueryObject failed for '{0}' (0x{1:X8}): {2}",
                filePath, err, new Win32Exception(err).Message));
        }

        try {
            if (contentType != CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED) {
                throw new InvalidOperationException(String.Format(
                    "Unexpected content type {0}; expected CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED ({1}).",
                    contentType, CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED));
            }

            var certs = new X509Certificate2Collection();
            if (hStore != IntPtr.Zero) {
                IntPtr pCertContext = IntPtr.Zero;
                while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != IntPtr.Zero) {
                    certs.Add(new X509Certificate2(pCertContext));
                }
            }
            return certs;
        } finally {
            if (hStore != IntPtr.Zero) CertCloseStore(hStore, 0);
            if (hMsg != IntPtr.Zero) CryptMsgClose(hMsg);
        }
    }
}
"@
    }
    return [AuthenticodeCertExtractor]::Extract($resolvedPath)
}
Function Test-MsiSignature {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $MSFT_ROOT_CERT_SUBJECT_PATTERN = "CN=Microsoft Root Certificate Authority*, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"

    Write-Verbose -Message "Validating MSI signature for: $FilePath" -Verbose

    if (-not (Test-Path $FilePath)) {
        throw "File not found for signature validation: $FilePath"
    }

    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath

        if (-not $signature) {
            throw "Failed to get MSI signature"
        }

        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "Signature not valid: Status: $($signature.Status), StatusMessage: $($signature.StatusMessage)"
        }

        $cert = $signature.SignerCertificate
        if (-not $cert) {
            throw "No signing certificate found"
        }

        # Extract certificates embedded in the Authenticode signature to supply as intermediates.
        # This ensures chain building succeeds even on locked-down networks where intermediate
        # CA certs are not in the local store and AIA download endpoints are unreachable.
        $embeddedCerts = $null
        try {
            $embeddedCerts = Get-EmbeddedAuthenticodeCertificates -FilePath $FilePath
        }
        catch {
            Write-Verbose -Message "Unable to extract embedded Authenticode certificates: $_" -Verbose
        }

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        # Allow expired certificates in the chain to maintain compatibility with older azcmagent versions. Get-AuthenticodeSignature already verified the
        # signature is valid (including timestamp checks for expired-but-timestamped certs). The
        # chain validation here only needs to confirm the root CA is Microsoft's.
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        if ($embeddedCerts -and $embeddedCerts.Count -gt 0) {
            $chain.ChainPolicy.ExtraStore.AddRange($embeddedCerts)
        }

        if (-not $chain.Build($cert)) {
            $chainErrors = ($chain.ChainStatus | ForEach-Object { $_.StatusInformation }) -join '; '
            throw "Certificate chain validation failed: $chainErrors"
        }

        Write-Verbose -Message "Certificate chain validation succeeded" -Verbose

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        if (-not ($rootCert.Subject -like $MSFT_ROOT_CERT_SUBJECT_PATTERN)) {
            throw "MSI is not signed by a trusted Microsoft root certificate. Found root: $($rootCert.Subject)"
        }

        Write-Verbose -Message "MSI signature validation completed successfully" -Verbose
    }
    catch {
        throw "Error validating signature of '$FilePath': $($_.Exception.Message)"
    }
}
Function Install-ArcAgent {

    # Install the package
    if (-not (Test-Path "$SourceFilesFullPath\AzureConnectedMachineAgent.msi" -ErrorAction SilentlyContinue)) {
        Write-Log -msg "AzureConnectedMachineAgent.msi file not found in the network folder. Exiting... " -msgtype ERROR
        exit
    }

    # If no local msi found, downloads it from the network share
    if (-not (Test-Path "$env:LOCALAPPDATA\AzureConnectedMachineAgent.msi" -ErrorAction SilentlyContinue)) {
        Copy-Item -Path "$SourceFilesFullPath\AzureConnectedMachineAgent.msi" -Destination "$env:LOCALAPPDATA" -Force
    }

    Test-MsiSignature -FilePath "$env:LOCALAPPDATA\AzureConnectedMachineAgent.msi"

    Write-Log -msg "Installing Azure Connected Machine Agent" -msgtype INFO
    Set-Location $workfolder
    $exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", "$env:LOCALAPPDATA\AzureConnectedMachineAgent.msi" , "/l*v", "Azcmagentinstallationlog.txt", "/qn") -Wait -Passthru).ExitCode
    $message = (net helpmsg $exitCode)
    if ($exitCode -ne 0) {

        Write-Log -msg "Installation failed: $message. See Azcmagentinstallationlog.txt for additional details" -msgtype ERROR
        throw $message
    }
    else {
        Write-Log -msg "Azure Connected Machine Agent installed. $message" -msgtype INFO
    }

}
Function Get-MsiVersion {

    Param (
        [IO.FileInfo]$path
    )
    
    $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
    $database = $windowsInstaller.GetType().InvokeMember(
        "OpenDatabase", "InvokeMethod", $Null,
        $windowsInstaller, @($path.FullName, 0)
    )
    
    $query = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
    $View = $database.GetType().InvokeMember(
        "OpenView", "InvokeMethod", $Null, $database, ($query)
    )
    
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)
    $record = $View.GetType().InvokeMember( "Fetch", "InvokeMethod", $Null, $View, $Null )
    $version = ($record.GetType().InvokeMember( "StringData", "GetProperty", $Null, $record, 1 ))
    
    return $version
}  
Function Update-ArcAgentVersion {

    Write-Log -msg "Checking Local Agent version for updates ..." -msgtype INFO

    #Checks Current Agent Version
    [Version]$LocalAgentVersion = (Get-ArcAgentstatus).Agentversion
    
    #Checks network share version
    Test-MsiSignature -FilePath "$SourceFilesFullPath\AzureConnectedMachineAgent.msi"
    [Version]$NetworkShareVersion = (Get-MsiVersion -path "$SourceFilesFullPath\AzureConnectedMachineAgent.msi")[1]
    #Compare versions


    if ($LocalAgentVersion -lt $NetworkShareVersion) {
        # New Agent Version Found
        Write-Log -msg "New Agent version found in network share folder: $($NetworkShareVersion.ToString()) , local version is $($LocalAgentVersion.ToString()). Executing update ..." -msgtype WARNING
    

        # Download the package
        Copy-Item -Path "$SourceFilesFullPath\AzureConnectedMachineAgent.msi" -Destination "$env:LOCALAPPDATA" -Force
    
        #Install the package
        Update-ArcAgent

        #Checks new Version
        [Version]$LocalAgentVersion = (Get-ArcAgentstatus).Agentversion
        Write-Log -msg "Azure Connected Machine Agent Version is now $($LocalAgentVersion.ToString())" -msgtype INFO 

    }
    else {
        #Latest Version Found
        Write-Log -msg "Machine has latest available version of the agent: $($LocalAgentVersion.ToString())" -msgtype INFO 
    }
}
Function Update-ArcAgent {

    # Update Agent

    Test-MsiSignature -FilePath "$env:LOCALAPPDATA\AzureConnectedMachineAgent.msi"

    Write-Log -msg "Updating Azure Connected Machine Agent" -msgtype INFO
    Set-Location $workfolder
    $exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", "$env:LOCALAPPDATA\AzureConnectedMachineAgent.msi" , "/l*v", "Azcmagentupdatesetup.txt", "/qn") -Wait -Passthru).ExitCode
    $message = (net helpmsg $exitCode)
    if ($exitCode -ne 0) {

        Write-Log -msg "Update failed: $message. See Azcmagentupdatesetup.txt for additional details" -msgtype ERROR
        throw $message
    }
    else {
        Write-Log -msg "Azure Connected Machine Agent updated. $message" -msgtype INFO
    }

}
Function Get-ServicePrincipalSecret {
    try {
        Copy-Item (Join-Path $SourceFilesFullPath "AzureArcDeployment.psm1") $workfolder -Force
        Import-Module (Join-Path $workfolder "AzureArcDeployment.psm1")
        $encryptedSecret = Get-Content (Join-Path $SourceFilesFullPath encryptedServicePrincipalSecret)
        $sps = [DpapiNgUtil]::UnprotectBase64($encryptedSecret)
    }
    catch {
        Write-Log -msg "Could not fetch service principal secret: $($_.Exception)" -msgtype ERROR
        return $false
    }
    finally {
        Remove-Item (Join-Path $workfolder "AzureArcDeployment.psm1") -Force
    }
    return $sps
}
Function Add-SiteTag {

    $adsite = (& "$env:windir\system32\nltest.exe" /dsgetsite)[0]

    if ($LastExitCode -eq 0) {
        Write-Log -msg "Tag Site:$adsite added to azure connected machine tags" -msgtype INFO
        $script:tags["Site"] = $adsite
    }
    else {
        Write-Log -msg "Could not determine machine's AD Site" -msgtype WARNING
        $script:tags["Site"] = "Unknown"
    }

}
Function Connect-ArcAgent {
    # Add AD site as a tag
    Add-SiteTag
    # Run connect command
    Write-Log -msg "Trying to Connect Azure Connected Machine Agent ..." -msgtype INFO

    $FinalTag = ($tags.GetEnumerator() | ForEach-Object -Process { "$($_.key)" + "=" + "'$($_.value)'" }) -join ","

    $sps = Get-ServicePrincipalSecret
    
    # if agent proxy is specified
    if ($AgentProxy) {
        $Proxyconf = & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" config set proxy.url $AgentProxy #Proxy Configured
    }

    $azcmagentPath = "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe"
    $baseArgs = @(
        "connect",
        "--resource-name", $env:computername,
        "--service-principal-id", $servicePrincipalClientId,
        "--service-principal-secret", $sps,
        "--resource-group", $ResourceGroup,
        "--tenant-id", $tenantid,
        "--location", $location,
        "--subscription-id", $subscriptionid,
        "--cloud", "AzureCloud",
        "--tags", $FinalTag,
        "--correlation-id", "478b97c2-9310-465a-87df-f21e66c2b248"
    )

    if ($PrivateLinkScopeId) {
        $baseArgs += "--private-link-scope"
        $baseArgs += $PrivateLinkScopeId

        # Append proxy bypass if AgentProxy is not empty
        if ($AgentProxy -ne "") {
            & "$azcmagentPath" config set proxy.bypass "Arc" # Bypass proxy for Arc services
        }
    }

    if ($GatewayId) {
        $baseArgs += "--gateway-id"
        $baseArgs += $GatewayId
    }

    # Execute the command
    $ConnectionOutput = & "$azcmagentPath" @baseArgs

    if ($LastExitCode -eq 0) {
        Write-Log -msg "Agent connected successfully!. To view your onboarded server(s), navigate to https://ms.portal.azure.com/#blade/Microsoft_Azure_HybridCompute/AzureArcCenterBlade/servers" -msgtype INFO
        return $True
    }

    else {
         
        #check for any errors in Agent connection
        Write-Log -msg "Agent Connection was unsuccessful. Waiting for logs to be generated..." -msgtype ERROR

        Start-Job -ScriptBlock {
            $script:Agentcode = $null
            do { 
                $script:Agentcode = Get-Content "$env:ProgramData\AzureConnectedMachineAgent\Log\azcmagent.log"-Tail 50 | Select-String 'AZCM\d*:[\s\w]*' | ForEach-Object { $_.matches } | Select-Object -Last 1 -ExpandProperty value 
            }
            Until ($null -ne $script:Agentcode)
            Write-Log -msg "Agent Code: $script:Agentcode" -msgtype ERROR
            Write-Log -msg "Check AZCM Agent codes here: https://docs.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard#agent-error-codes" -msgtype INFO
        } | Wait-Job -Timeout 30
        
        return $false
    }
}
Function Repair-ArcAgentConnection {
     
    #TODO: 
    #The Machine could be moved, it has to maintaing the same config:
    #$RegistrationInfo =  Get-Registrationinfo
    #$ConnectionOuput = & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --service-principal-id $servicePrincipalClientId --service-principal-secret $RegistrationInfo --resource-group $Agentconfig.resourceGroup --tenant-id $Agentconfig.tenantId --location $Agentconfig.location --subscription-id $Agentconfig.subscriptionId  --cloud $Agentconfig.Cloud --tags $FinalTag --correlation-id $Agentconfig.correlationId
            
}
Function Send-ArcData {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [psobject]$Data,
        [Parameter(Mandatory = $true)]
        [System.String]$Path
    )

    Write-Log -msg "Sending information to central Shared folder ..." -msgtype INFO
    $ParentPath = Split-Path -Path $path -Parent
    if ($? -eq $false) { Write-Log -msg "$($error[0].Exception)" -msgtype ERROR }
    
    if (-not(Test-Path ($ParentPath))) { 
        New-Item -Path $ParentPath -ItemType Directory -Force 
        if ($? -eq $false) { Write-Log -msg "$($error[0].Exception)" -msgtype ERROR }
    }
    $Data | Export-Clixml -Path $Path -Force
    if ($? -eq $false) { Write-Log -msg "$($error[0].Exception)" -msgtype ERROR }
    
}
Function Test-ArcAgentConnection {

    #Check if the Azure Connected Machine Agent is connected

    try { $Agentresponse = Invoke-WebRequest -Uri "http://localhost:40342/agentstatus" -UseBasicParsing -ErrorAction Stop }
    catch { Write-Log "There was an error when trying to get agent status: $($_.Exception)" -msgtype ERROR; throw $_.Exception }
    $azcmagentstatus = $Agentresponse | ConvertFrom-Json

    if ($azcmagentstatus.status -ne "Connected") {
        return $false
    }
    else {
        return $true
    }
}
Function Test-ArcService {
    #Check if the Azure Hybrid Instance Metadata Service is already installed
    try { Get-Service himds -ErrorAction Stop }
    catch {
        Write-Log -msg "No Hybrid Instance Metadate Service installed" -msgtype ERROR
        return $false
    }
    Write-Log -msg "Machine has the Hybrid Instance Metadata Service already installed ..." -msgtype INFO
    return $true

}
Function Write-Log {
    Param (
        [System.String]$msg,
    
        [ValidateSet("INFO", "ERROR", "WARNING")]
        [System.String]$msgtype,

        [switch]$Force
    )
    if ($PSBoundParameters.ContainsKey("Force")) {
        Write-Output -InputObject "$(Get-Date -Format ("[yyyy-MM-dd][HH:mm:ss]")) $msgtype $msg" | Out-File $logpath
    }
    else {
        Write-Output -InputObject "$(Get-Date -Format ("[yyyy-MM-dd][HH:mm:ss]")) $msgtype $msg" | Out-File $logpath -Append
    }
}

#endregion


# MAIN

if (-not (Test-Path $workfolder))
{ New-Item -Path $workfolder -Force -ItemType Directory | Out-Null }

#Reduces by 1/4 the log file if excedees of 10mb
if ((Get-Item $logpath -ErrorAction SilentlyContinue).Length -gt 10mb) {

    $content = Get-Content $logpath
    $content[[int]($content.Length / 4)..($content.length - 1)] | Out-File $logpath -Force
}

Write-Log -msg "=========================================" -msgtype INFO
Write-Log -msg "Starting Azure Arc Onboarding process ..." -msgtype INFO
Write-Log -msg "Sources full path: $SourceFilesFullPath" -msgtype INFO
Write-Log -msg "Logging network full path: $LoggingNetworkPath" -msgtype INFO

$hash = @{
    Computer            = $env:COMPUTERNAME
    OSVersion           = (Get-WmiObject -Class win32_Operatingsystem).Caption
    FrameworkVersion    = ""
    PowershellVersion   = ($PSVersionTable.PSVersion.ToString()).substring(0, 3)
    AzureVM             = $false
    ArcCompatible       = $true
    AgentStatus         = ""
    AgentLastHeartbeat  = ""
    AgentErrorCode      = ""
    AgentErrorTimestamp = (New-Object -TypeName datetime -ArgumentList ($null))
    AgentErrorDetails   = ""
    httpsProxy          = ""
}

$ArcOnboardingData = New-Object -TypeName PSobject -Property $hash

# Check Framework version
$FrameworkRegistry = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client"
try {
    Test-Path -Path $FrameworkRegistry -ErrorAction Stop | Out-Null
    [version]$FWVersion = Get-ItemProperty -Path $FrameworkRegistry -Name Version -ErrorAction Stop | Select-Object -ExpandProperty Version
    $ArcOnboardingData.FrameworkVersion = $FWVersion.ToString()

}
catch {
    Write-Log -msg "Framework version is 3.5 or less and it's unsupported" -msgtype ERROR
        
    $ArcOnboardingData.FrameworkVersion = "3.5 or less"
    $ArcOnboardingData.ArcCompatible = $false

}

if (($FWVersion.major -lt 4) -or (($FWVersion.Major -eq 4) -and ($FWVersion.Minor -lt 6))) {
    Write-Log -msg "Framework version $($FWVersion.ToString()) is unsupported" -msgtype ERROR    
    
    $ArcOnboardingData.ArcCompatible = $false

}
else { 
    Write-Log -msg "Machine has Framework version $($FWVersion.ToString()), this is supported" -msgtype INFO
}

#Check PowerShell Version (Powershell 4 is required)

if ($PSVersionTable.PSVersion.Major -lt 4) {
    Write-Log -msg "Machine has Powershell version $($PSVersionTable.PSVersion.Major), minimum version required is PowerShell v4." -msgtype ERROR
    $ArcOnboardingData.ArcCompatible = $false
}
else {
    Write-Log -msg "Machine has PowerShell version version $($PSVersionTable.PSVersion.Major), this is supported" -msgtype INFO
}


#Check if it's an Azure VM
try {
    $TestAzuremachine = Invoke-RestMethod -Headers @{"Metadata" = "true" } `
        -Method GET -Proxy $Null -Uri "http://169.254.169.254/metadata/instance?api-version=2020-09-01"`
        -TimeoutSec 10 -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 64
}
catch {}
If ($Null -ne $TestAzuremachine) {
    Write-Log -msg "Machine is an Azure VM, it won't be onboarded in Azure Arc" -msgtype ERROR
    $ArcOnboardingData.AzureVM = $true
    $ArcOnboardingData.ArcCompatible = $false
    Write-Log -msg "Exiting Onboarding Process" -msgtype INFO
    exit
}
else {
    Write-Log -msg "Machine is not an Azure VM. Continuing the onboarding process" -msgtype INFO
    $ArcOnboardingData.AzureVM = $false
}

#In case the onboarding is in AssessOnly mode, the onboarding process posts the data and exits
if ($PSBoundParameters.ContainsKey('AssessOnly')) {
    Write-Log -msg "Arc GPO Onboarding is in AssessOnly mode. Remove the -AssessOnly parameter from the scheduled task in the GPO if you want the machines to be onboarded in Azure ARC." -msgtype WARNING
    Send-ArcData -Data $ArcOnboardingData -Path "$LoggingNetworkPath\$($env:COMPUTERNAME).xml"
    Write-Log -msg "End of the Azure Arc Onboarding process..." -msgtype INFO
    exit
}

#Post to share if Machine has dependencies to solve

if (($ArcOnboardingData.AzureVM -eq $false) -and ($ArcOnboardingData.ArcCompatible -eq $false)) {
    Write-Log -msg "Machine doesn't meet the minimum requirements for Azure Arc: Windows PowerShell 4 and NET Framework 4.6, or it is an Azure VM." -msgtype ERROR
    Send-ArcData -Data $ArcOnboardingData -Path "$LoggingNetworkPath\$($env:COMPUTERNAME).xml"
    Write-Log -msg "End of the Azure Arc Onboarding process..." -msgtype INFO

    exit
}

#region Onboarding Process


#Checks Arc Service
if ((Test-ArcService) -eq $false) {
    Install-ArcAgent
    $StartConnection = Get-Date
    if ((Connect-ArcAgent) -eq $false) {
        Get-ArcAgentErrorLogs -since $StartConnection
        Write-Log -msg "End of the Azure Arc Onboarding process." -msgtype INFO
        exit
    }

}
else {
    # the Azure Hybrid Instance Metadata Service is already installed

    #Ensures server has the latest Agent Version
    Update-ArcAgentVersion
}


#Checks Agent Connectivity

if ((Test-ArcAgentConnection) -eq $false) {
    
    #Log info locally
    Write-Log -msg "Azure Connected Machine Agent is not connected ..." -msgtype ERROR
    Get-ArcAgentErrorLogs -since (Get-Date).AddMinutes(-7)

    $AgentProxyConfigured = (Get-ArcAgentstatus).httpsProxy
    
    if ("" -eq $AgentProxyConfigured) {
        Write-Log -msg "Machine has no proxy configured" -msgtype INFO
    }
    else { Write-Log -msg "Machine has the following proxy configured: $AgentProxyConfigured" -msgtype INFO }
    
    if (-not (Test-Path "$env:Programdata\AzureConnectedMachineAgent\Config\agentconfig.json" )) {
        Write-Log -msg "This machine has never been connected to Azure Arc, retrying one more time ..." -msgtype ERROR
        $StartConnection = Get-Date
        if ((Connect-ArcAgent) -eq $false) {
            Get-ArcAgentErrorLogs -since $StartConnection
        }
        else {
            # Machine connected successfuly
            Write-Log -msg "End of the Azure Arc Onboarding process." -msgtype INFO
            exit
        }
    }

    #Prepare Information
    $ArcAgentInfo = Get-ArcAgentstatus -logtype "error", "info" -loglocally  # The status is also logged locally
    $ArcOnboardingData.AgentStatus = $ArcAgentInfo.status
    $ArcOnboardingData.AgentErrorCode = $script:AgentCode
    $ArcOnboardingData.AgentLastHeartbeat = $ArcAgentInfo.lastHeartbeat
    $ArcOnboardingData.AgentErrorTimestamp = [datetime]([regex]::match(($script:azcmagentErrors | Select-Object -Last 1 ), '^time="([\d\w\W]*)"\s').groups[1].value)
    $ArcOnboardingData.AgentErrorDetails = [regex]::match(($script:azcmagentErrors | Select-Object -Last 1 ), 'msg="[\w\W\s]*').Groups[0].Value
    $ArcOnboardingData.httpsProxy = $ArcAgentInfo.httpsProxy


    #Send information to Share Folder
    Send-ArcData -Data $ArcOnboardingData -Path "$LoggingNetworkPath\NotConnected\$($env:COMPUTERNAME).NotConnected.xml"

}
else {
    Get-ArcAgentstatus -logtype "info" -loglocally 
    Write-Log -msg "Azure Connected Machine Agent is already connected." -msgtype INFO
}
Write-Log -msg "End of the Azure Arc Onboarding process." -msgtype INFO

#endregion
