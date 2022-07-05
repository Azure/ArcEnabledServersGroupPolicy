# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# C# code to call into CNG DPAPI 
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