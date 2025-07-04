#requires -Modules ActiveDirectory
<#
.DESCRIPTION
    This Script can be used to renew the encrypted secret file of the Service Principal used for Azure Arc onboarding
    at scale.
    The secret is encrypted and saved in the 'encryptedServicePrincipalSecret' file, that was to be copied to the 
    Azure Arc deployment share. By default this share is 'AzureArcOnboard\AzureArcDeploy'


.PARAMETER ServicePrincipalSecret
    Value of the new Service Principal Secret created in Azure Active Directory

.PARAMETER DomainFQDNs
    List of Domains, in the FQND from, that need permissions to decrypt the secret. E.g. "domain.local","domain2.local"
 
.EXAMPLE
   This example generates a new encrypted secret and saves it to the encryptedServicePrincipalSecret file

   .\RenewSPSecretDPAPI.ps1 -ServicePrincipalSecret cwD7Q~MC36ei5BhH2pwHviqv6avUwMz9p2_hkbcz -DomainFQDNs "contoso.local"
   .\RenewSPSecretDPAPI.ps1 -ServicePrincipalSecret cwD7Q~MC36ei5BhH2pwHviqv6avUwMz9p2_hkbcz -DomainFQDNs "domain.local","domain2.local"
#>

Param (
    [Parameter(Mandatory = $true)]
    [string]$ServicePrincipalSecret,
    [string[]]$DomainFQDNs
)

#region Funtions and types definition
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class DpapiNgUtil
{
    public static string ProtectBase64(string protectionDescriptor, string input)
    {
        byte[] output = Protect(protectionDescriptor, Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(output);
    }

    public static string UnprotectBase64(string input)
    {
        byte[] bytes = Convert.FromBase64String(input);
        byte[] output = Unprotect(bytes);
        return Encoding.UTF8.GetString(output);
    }
    
    public static byte[] Protect(string protectionDescriptor, byte[] data)
    {
        using (NCryptProtectionDescriptorHandle handle = NCryptProtectionDescriptorHandle.Create(protectionDescriptor))
        {
            return Protect(handle, data);
        }
    }

    internal static byte[] Protect(NCryptProtectionDescriptorHandle descriptor, byte[] data)
    {
        uint cbProtectedBlob;
        LocalAllocHandle protectedBlobHandle;
        int status = NativeMethods.NCryptProtectSecret(descriptor, NativeMethods.NCRYPT_SILENT_FLAG, data, (uint)data.Length, IntPtr.Zero, IntPtr.Zero, out protectedBlobHandle, out cbProtectedBlob);
        if(status != 0)
        {
            throw new CryptographicException(status);
        }

        using (protectedBlobHandle)
        {
            byte[] retVal = new byte[cbProtectedBlob];
            Marshal.Copy(protectedBlobHandle.DangerousGetHandle(), retVal, 0, retVal.Length);
            return retVal;
        }
    }

    public static byte[] Unprotect(byte[] protectedData)
    {
        uint cbData;
        LocalAllocHandle dataHandle;
        int status = NativeMethods.NCryptUnprotectSecret(IntPtr.Zero, NativeMethods.NCRYPT_SILENT_FLAG, protectedData, (uint)protectedData.Length, IntPtr.Zero, IntPtr.Zero, out dataHandle, out cbData);
        if (status != 0)
        {
            throw new CryptographicException(status);
        }

        using (dataHandle)
        {
            byte[] retVal = new byte[cbData];
            Marshal.Copy(dataHandle.DangerousGetHandle(), retVal, 0, retVal.Length);
            return retVal;
        }
    }
}

internal class LocalAllocHandle : SafeHandle
{
    // Called by P/Invoke when returning SafeHandles
    private LocalAllocHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    // Do not provide a finalizer - SafeHandle's critical finalizer will
    // call ReleaseHandle for you.

    public override bool IsInvalid
    {
        get { return handle == IntPtr.Zero; }
    }

    protected override bool ReleaseHandle()
    {
        IntPtr retVal = NativeMethods.LocalFree(handle);
        return (retVal == IntPtr.Zero);
    }
}

internal class NCryptProtectionDescriptorHandle : SafeHandle
{
    // Called by P/Invoke when returning SafeHandles
    private NCryptProtectionDescriptorHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    // Do not provide a finalizer - SafeHandle's critical finalizer will
    // call ReleaseHandle for you.

    public override bool IsInvalid
    {
        get { return handle == IntPtr.Zero; }
    }

    public static NCryptProtectionDescriptorHandle Create(string protectionDescriptor)
    {
        NCryptProtectionDescriptorHandle descriptorHandle;
        int status = NativeMethods.NCryptCreateProtectionDescriptor(protectionDescriptor, 0, out descriptorHandle);
        if (status != 0) {
            throw new CryptographicException(status);
        }
        return descriptorHandle;
    }

    protected override bool ReleaseHandle()
    {
        int retVal = NativeMethods.NCryptCloseProtectionDescriptor(handle);
        return (retVal == 0);
    }
}

internal static class NativeMethods
{
    private const string KERNEL32LIB = "kernel32.dll";
    private const string NCRYPTLIB = "ncrypt.dll";

    internal const uint NCRYPT_SILENT_FLAG = 0x00000040;
    

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366730(v=vs.85).aspx
    [DllImport(KERNEL32LIB, SetLastError = true)]
    internal static extern IntPtr LocalFree(
        [In] IntPtr handle);

    // http://msdn.microsoft.com/en-us/library/windows/desktop/hh706799(v=vs.85).aspx
    [DllImport(NCRYPTLIB)]
    internal extern static int NCryptCloseProtectionDescriptor(
        [In] IntPtr hDescriptor);

    // http://msdn.microsoft.com/en-us/library/windows/desktop/hh706800(v=vs.85).aspx
    [DllImport(NCRYPTLIB, CharSet = CharSet.Unicode)]
    internal extern static int NCryptCreateProtectionDescriptor(
        [In] string pwszDescriptorString,
        [In] uint dwFlags,
        [Out] out NCryptProtectionDescriptorHandle phDescriptor);

    // http://msdn.microsoft.com/en-us/library/windows/desktop/hh706802(v=vs.85).aspx
    [DllImport(NCRYPTLIB)]
    internal extern static int NCryptProtectSecret(
        [In] NCryptProtectionDescriptorHandle hDescriptor,
        [In] uint dwFlags,
        [In] byte[] pbData,
        [In] uint cbData,
        [In] IntPtr pMemPara,
        [In] IntPtr hWnd,
        [Out] out LocalAllocHandle ppbProtectedBlob,
        [Out] out uint pcbProtectedBlob);

    // http://msdn.microsoft.com/en-us/library/windows/desktop/hh706811(v=vs.85).aspx
    [DllImport(NCRYPTLIB)]
    internal extern static int NCryptUnprotectSecret(
        [In] IntPtr phDescriptor,
        [In] uint dwFlags,
        [In] byte[] pbProtectedBlob,
        [In] uint cbProtectedBlob,
        [In] IntPtr pMemPara,
        [In] IntPtr hWnd,
        [Out] out LocalAllocHandle ppbData,
        [Out] out uint pcbData);
}
"@

#endregion

#Get SID of Domain Computers and Domain Controllers groups for each domain

$sidlist = @()
foreach ($DomainFQDN in $DomainFQDNs) {
    $DomainComputersSID = (Get-ADDomain -Identity $DomainFQDN).DomainSID.Value + '-515'
    $DomainControllersSID = (Get-ADDomain -Identity $DomainFQDN).DomainSID.Value + '-516'    
    $DomainComputersSID = "SID=" + $DomainComputersSID
    $DomainControllersSID = "SID=" + $DomainControllersSID
    $sidlist += $DomainComputersSID
    $sidlist += $DomainControllersSID
}

#Generate the encryption secret and assign permissions to AD groups
$descriptor = ($sidlist -join " OR ")
Write-Verbose -Message "Using protection descriptor $descriptor"
$protectedSecret = [DpapiNgUtil]::ProtectBase64($descriptor, $ServicePrincipalSecret)


#Save encrypted info to text file

$protectedSecret | Out-File -FilePath  ".\encryptedServicePrincipalSecret" -Force

Write-Host -ForegroundColor Green "Encrypted secret has been saved to 'encryptedServicePrincipalSecret' file`n"
Write-Host -ForegroundColor Green "Please copy the file to the Azure Arc Deployment share. Default sshare is 'AzureArcOnboard\AzureArcDeploy'"
notepad encryptedServicePrincipalSecret
