namespace MalPacker.PE;

public sealed class PeData
{
    public byte[] RawBytes { get; set; } = [];
    public bool Is64Bit { get; init; }
    public int PeHeaderOffset { get; init; }
    public uint EntryPointRva { get; init; }
    public uint SizeOfImage { get; set; }
    public uint SizeOfHeaders { get; init; }
    public uint FileAlignment { get; init; }
    public uint SectionAlignment { get; init; }
    public ushort NumberOfSections { get; set; }
    public List<PeSection> Sections { get; init; } = [];
}

public sealed class PeSection
{
    public string Name { get; set; } = string.Empty;
    public uint VirtualAddress { get; set; }
    public uint VirtualSize { get; set; }
    public uint PointerToRawData { get; set; }
    public uint SizeOfRawData { get; set; }
    public uint Characteristics { get; set; }
    public byte[] RawData { get; set; } = [];
    public bool IsCompressed { get; set; }
    public bool IsEncrypted { get; set; }
    public byte[]? EncryptionKey { get; set; }
}
