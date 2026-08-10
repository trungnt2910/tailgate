[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$desktop = 'HKCU:\Control Panel\Desktop'
New-ItemProperty `
    -Path $desktop `
    -Name LogPixels `
    -PropertyType DWord `
    -Value 96 `
    -Force | Out-Null
New-ItemProperty `
    -Path $desktop `
    -Name Win8DpiScaling `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null

$accessibility = 'HKCU:\Software\Microsoft\Accessibility'
New-Item -Path $accessibility -Force | Out-Null
New-ItemProperty `
    -Path $accessibility `
    -Name TextScaleFactor `
    -PropertyType DWord `
    -Value 100 `
    -Force | Out-Null

$nativeMethods = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class UwpTestEnvironmentNativeMethods
{
    private const uint SpiGetHighContrast = 0x0042;
    private const uint SpiSetHighContrast = 0x0043;
    private const uint SpiSetClientAreaAnimation = 0x1043;
    private const uint HighContrastOn = 0x00000001;
    private const uint UpdateProfile = 0x00000001;
    private const uint SendChange = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct HighContrast
    {
        public uint Size;
        public uint Flags;
        public IntPtr DefaultScheme;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(
        uint action,
        uint parameter,
        ref HighContrast value,
        uint update);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(
        uint action,
        uint parameter,
        IntPtr value,
        uint update);

    public static void DisableHighContrast()
    {
        HighContrast value = new HighContrast();
        value.Size = (uint)Marshal.SizeOf(typeof(HighContrast));
        if (!SystemParametersInfo(SpiGetHighContrast, value.Size, ref value, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        value.Flags &= ~HighContrastOn;
        if (!SystemParametersInfo(
                SpiSetHighContrast,
                value.Size,
                ref value,
                UpdateProfile | SendChange))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public static void DisableAnimations()
    {
        if (!SystemParametersInfo(
                SpiSetClientAreaAnimation,
                0,
                IntPtr.Zero,
                UpdateProfile | SendChange))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@

Add-Type -TypeDefinition $nativeMethods -Language CSharp
[UwpTestEnvironmentNativeMethods]::DisableHighContrast()
[UwpTestEnvironmentNativeMethods]::DisableAnimations()
