namespace MalPacker.PE;

using System.Text;

public sealed class ImportDirectory
{
    public static List<ImportDescriptor> Parse(byte[] peBytes, uint importRva, List<PeSection> sections)
    {
        var descriptors = new List<ImportDescriptor>();
        if (importRva == 0) return descriptors;

        int fileOffset = RvaToFileOffset(importRva, sections);
        if (fileOffset < 0) return descriptors;

        while (fileOffset + 20 <= peBytes.Length)
        {
            uint originalFirstThunk = BitConverter.ToUInt32(peBytes, fileOffset);
            uint timeDateStamp = BitConverter.ToUInt32(peBytes, fileOffset + 4);
            uint forwarderChain = BitConverter.ToUInt32(peBytes, fileOffset + 8);
            uint nameRva = BitConverter.ToUInt32(peBytes, fileOffset + 12);
            uint firstThunk = BitConverter.ToUInt32(peBytes, fileOffset + 16);

            if (nameRva == 0) break;

            int nameOffset = RvaToFileOffset(nameRva, sections);
            string dllName = nameOffset >= 0 ? ReadNullTerminated(peBytes, nameOffset) : string.Empty;

            descriptors.Add(new ImportDescriptor
            {
                OriginalFirstThunk = originalFirstThunk,
                TimeDateStamp = timeDateStamp,
                ForwarderChain = forwarderChain,
                NameRva = nameRva,
                FirstThunk = firstThunk,
                DllName = dllName
            });

            fileOffset += 20;
        }

        return descriptors;
    }

    private static int RvaToFileOffset(uint rva, List<PeSection> sections)
    {
        foreach (var section in sections)
        {
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
            {
                return (int)(rva - section.VirtualAddress + section.PointerToRawData);
            }
        }
        return -1;
    }

    private static string ReadNullTerminated(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }
}

public sealed class ImportDescriptor
{
    public uint OriginalFirstThunk { get; init; }
    public uint TimeDateStamp { get; init; }
    public uint ForwarderChain { get; init; }
    public uint NameRva { get; init; }
    public uint FirstThunk { get; init; }
    public string DllName { get; init; } = string.Empty;
}
