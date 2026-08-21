namespace MalPacker.PE;

public sealed class RelocationTable
{
    public static List<RelocationBlock> Parse(byte[] peBytes, uint relocationRva, List<PeSection> sections)
    {
        var blocks = new List<RelocationBlock>();
        if (relocationRva == 0) return blocks;

        int fileOffset = RvaToFileOffset(relocationRva, sections);
        if (fileOffset < 0) return blocks;

        while (fileOffset + 8 <= peBytes.Length)
        {
            uint pageRva = BitConverter.ToUInt32(peBytes, fileOffset);
            uint blockSize = BitConverter.ToUInt32(peBytes, fileOffset + 4);

            if (blockSize == 0 || blockSize < 8) break;

            int entryCount = (int)(blockSize - 8) / 2;
            var entries = new List<RelocationEntry>();

            for (int i = 0; i < entryCount; i++)
            {
                ushort raw = BitConverter.ToUInt16(peBytes, fileOffset + 8 + i * 2);
                int type = raw >> 12;
                int offset = raw & 0xFFF;

                if (type != 0)
                {
                    entries.Add(new RelocationEntry
                    {
                        Type = (RelocationType)type,
                        Offset = offset
                    });
                }
            }

            blocks.Add(new RelocationBlock
            {
                PageRva = pageRva,
                Entries = entries
            });

            fileOffset += (int)blockSize;
        }

        return blocks;
    }

    public static byte[] Build(List<RelocationBlock> blocks)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        foreach (var block in blocks)
        {
            int entryCount = block.Entries.Count;
            if (entryCount % 2 != 0) entryCount++;

            uint blockSize = (uint)(8 + entryCount * 2);
            writer.Write(block.PageRva);
            writer.Write(blockSize);

            foreach (var entry in block.Entries)
            {
                ushort value = (ushort)(((int)entry.Type << 12) | (entry.Offset & 0xFFF));
                writer.Write(value);
            }

            if (block.Entries.Count % 2 != 0)
                writer.Write((ushort)0);
        }

        return ms.ToArray();
    }

    private static int RvaToFileOffset(uint rva, List<PeSection> sections)
    {
        foreach (var section in sections)
        {
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                return (int)(rva - section.VirtualAddress + section.PointerToRawData);
        }
        return -1;
    }
}

public sealed class RelocationBlock
{
    public uint PageRva { get; init; }
    public List<RelocationEntry> Entries { get; init; } = [];
}

public sealed class RelocationEntry
{
    public RelocationType Type { get; init; }
    public int Offset { get; init; }
}

public enum RelocationType
{
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    Dir64 = 10
}
