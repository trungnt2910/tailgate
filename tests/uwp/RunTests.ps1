[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ManifestPath,

    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $TestExecutable,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]] $GoogleTestArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-TestUri
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $Arguments
    )

    $query = @(foreach ($argument in $Arguments)
    {
        if (-not $argument.StartsWith('--', [StringComparison]::Ordinal))
        {
            throw "Unsupported GoogleTest argument: $argument"
        }

        $item = $argument.Substring(2)
        $separator = $item.IndexOf('=')
        if ($separator -lt 0)
        {
            [Uri]::EscapeDataString($item)
            continue
        }

        $name = [Uri]::EscapeDataString($item.Substring(0, $separator))
        $value = [Uri]::EscapeDataString($item.Substring($separator + 1))
        "$name=$value"
    })

    $uri = 'tailgate-tests://run'
    if ($query.Count -gt 0)
    {
        $uri += '?' + ($query -join '&')
    }
    return [Uri]$uri
}

$protocolActivatorSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Tailgate.Uwp.Testing
{
    public static class ProtocolActivator
    {
        private const int ErrorInvalidParameter = 87;
        private const uint Infinite = 0xFFFFFFFF;
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint Synchronize = 0x00100000;
        private const uint WaitObject0 = 0;
        private static readonly Guid ApplicationActivationManagerClassId =
            new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C");
        private static readonly Guid ShellItemId =
            new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
        private static readonly Guid ShellItemArrayId =
            new Guid("B63EA76D-1F85-456F-A19C-48159EFA858B");

        [ComImport]
        [Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IApplicationActivationManager
        {
            [PreserveSig]
            int ActivateApplication(
                [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
                [MarshalAs(UnmanagedType.LPWStr)] string arguments,
                uint options,
                out uint processId);

            [PreserveSig]
            int ActivateForFile(
                [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
                IntPtr itemArray,
                [MarshalAs(UnmanagedType.LPWStr)] string verb,
                out uint processId);

            [PreserveSig]
            int ActivateForProtocol(
                [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
                IntPtr itemArray,
                out uint processId);
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHCreateItemFromParsingName(
            string path,
            IntPtr bindContext,
            ref Guid interfaceId,
            out IntPtr shellItem);

        [DllImport("shell32.dll")]
        private static extern int SHCreateShellItemArrayFromShellItem(
            IntPtr shellItem,
            ref Guid interfaceId,
            out IntPtr shellItemArray);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint desiredAccess,
            bool inheritHandle,
            uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        public static void ActivateAndWait(string appUserModelId, string uri)
        {
            IntPtr shellItem = IntPtr.Zero;
            IntPtr shellItemArray = IntPtr.Zero;
            IntPtr process = IntPtr.Zero;
            IApplicationActivationManager manager = null;
            try
            {
                Guid shellItemId = ShellItemId;
                Marshal.ThrowExceptionForHR(
                    SHCreateItemFromParsingName(
                        uri,
                        IntPtr.Zero,
                        ref shellItemId,
                        out shellItem));
                Guid shellItemArrayId = ShellItemArrayId;
                Marshal.ThrowExceptionForHR(
                    SHCreateShellItemArrayFromShellItem(
                        shellItem,
                        ref shellItemArrayId,
                        out shellItemArray));

                Type managerType = Type.GetTypeFromCLSID(
                    ApplicationActivationManagerClassId,
                    true);
                manager = (IApplicationActivationManager)Activator.CreateInstance(managerType);
                uint processId;
                Marshal.ThrowExceptionForHR(
                    manager.ActivateForProtocol(appUserModelId, shellItemArray, out processId));
                process = OpenProcess(
                    Synchronize | ProcessQueryLimitedInformation,
                    false,
                    processId);
                if (process == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorInvalidParameter)
                    {
                        return;
                    }
                    throw new Win32Exception(error);
                }
            }
            finally
            {
                if (manager != null)
                {
                    Marshal.FinalReleaseComObject(manager);
                }
                if (shellItemArray != IntPtr.Zero)
                {
                    Marshal.Release(shellItemArray);
                }
                if (shellItem != IntPtr.Zero)
                {
                    Marshal.Release(shellItem);
                }
            }

            try
            {
                uint waitResult = WaitForSingleObject(process, Infinite);
                if (waitResult != WaitObject0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                CloseHandle(process);
            }
        }
    }
}
'@

try
{
    $resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
    if (-not (Test-Path -LiteralPath $TestExecutable -PathType Leaf))
    {
        throw "The UWP test executable was not built: $TestExecutable"
    }

    [xml] $manifest = Get-Content -LiteralPath $resolvedManifest -Raw
    $namespaces = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespaces.AddNamespace('appx', $manifest.DocumentElement.NamespaceURI)
    $identity = $manifest.SelectSingleNode('/appx:Package/appx:Identity', $namespaces)
    $application =
        $manifest.SelectSingleNode('/appx:Package/appx:Applications/appx:Application', $namespaces)
    if ($null -eq $identity -or $null -eq $application)
    {
        throw "The AppX manifest is missing its package identity or application: $resolvedManifest"
    }

    $processName = [IO.Path]::GetFileNameWithoutExtension($application.Executable)
    Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
    Get-AppxPackage -Name $identity.Name | ForEach-Object `
    {
        Remove-AppxPackage -Package $_.PackageFullName
    }
    Add-AppxPackage -Register $resolvedManifest -ForceApplicationShutdown

    $package = Get-AppxPackage -Name $identity.Name |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $package)
    {
        throw "The UWP test package was not registered: $($identity.Name)"
    }

    if ($null -eq ('Tailgate.Uwp.Testing.ProtocolActivator' -as [Type]))
    {
        Add-Type -TypeDefinition $protocolActivatorSource -Language CSharp
    }

    $applicationData =
        [Windows.Management.Core.ApplicationDataManager]::
            CreateForPackageFamily($package.PackageFamilyName)
    $outputFileName = "$processName.output.txt"
    $exitFileName = "$processName.exit.txt"
    $outputPath = Join-Path $applicationData.TemporaryFolder.Path $outputFileName
    $exitPath = Join-Path $applicationData.TemporaryFolder.Path $exitFileName
    Remove-Item `
        -LiteralPath $outputPath, $exitPath `
        -Force `
        -ErrorAction SilentlyContinue

    $appUserModelId = "$($package.PackageFamilyName)!$($application.Id)"
    $testUri = ConvertTo-TestUri -Arguments $GoogleTestArguments
    [Tailgate.Uwp.Testing.ProtocolActivator]::ActivateAndWait(
        $appUserModelId,
        $testUri.AbsoluteUri)
    if (-not (Test-Path -LiteralPath $exitPath -PathType Leaf))
    {
        throw "The UWP test harness produced no exit code: $exitPath"
    }
    if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf))
    {
        throw "The UWP test harness produced no GoogleTest output: $outputPath"
    }

    $exitCode = [int](Get-Content -LiteralPath $exitPath -Raw)
    Write-Verbose "UWP GoogleTest output: $outputPath"
    $output = Get-Content -LiteralPath $outputPath -Raw
    [Console]::Out.Write($output)
    exit $exitCode
}
catch
{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
