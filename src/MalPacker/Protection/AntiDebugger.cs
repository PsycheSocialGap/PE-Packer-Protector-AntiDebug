namespace MalPacker.Protection;

using System.Diagnostics;
using System.Runtime.InteropServices;

public static class AntiDebugger
{
    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebuggerPresent);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int processInfoClass, out IntPtr info, int size, out int returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    public static bool IsBeingDebugged()
    {
        return CheckPeb()
            || CheckRemoteDebugger()
            || CheckNtGlobalFlag()
            || CheckDebugPort()
            || CheckProcessDebugFlags()
            || CheckHardwareBreakpoints();
    }

    private static bool CheckPeb()
    {
        return IsDebuggerPresent();
    }

    private static bool CheckRemoteDebugger()
    {
        CheckRemoteDebuggerPresent(GetCurrentProcess(), out bool isDebuggerPresent);
        return isDebuggerPresent;
    }

    private static bool CheckNtGlobalFlag()
    {
        IntPtr peb = GetPebAddress();
        if (peb == IntPtr.Zero) return false;

        int ntGlobalFlag = Marshal.ReadInt32(peb + 0xBC);
        return (ntGlobalFlag & 0x70) != 0; // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    }

    private static bool CheckDebugPort()
    {
        int status = NtQueryInformationProcess(GetCurrentProcess(), 7, out IntPtr debugPort, IntPtr.Size, out _);
        return status == 0 && debugPort != IntPtr.Zero;
    }

    private static bool CheckProcessDebugFlags()
    {
        int status = NtQueryInformationProcess(GetCurrentProcess(), 0x1F, out IntPtr debugFlags, 4, out _);
        return status == 0 && debugFlags == IntPtr.Zero;
    }

    private static bool CheckHardwareBreakpoints()
    {
        var context = new CONTEXT { ContextFlags = 0x00010010 };
        IntPtr thread = GetCurrentThread();

        if (!GetThreadContext(thread, ref context))
            return false;

        return context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0;
    }

    private static IntPtr GetPebAddress()
    {
        int status = NtQueryInformationProcess(GetCurrentProcess(), 0, out IntPtr pbi, IntPtr.Size * 6, out _);
        if (status != 0) return IntPtr.Zero;
        return Marshal.ReadIntPtr(pbi + IntPtr.Size);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT
    {
        public uint ContextFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    }
}
