namespace MalPacker.Core;

using System.Text;
using MalPacker.Models;
using MalPacker.PE;

public sealed class ImportRebuilder
{
    private readonly PeData _peData;

    public ImportRebuilder(PeData peData)
    {
        _peData = peData;
    }

    public byte[] BuildImportTable(List<ImportEntry> imports)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        int descriptorSize = (imports.Count + 1) * 20;
        int namesOffset = descriptorSize;

        var nameOffsets = new List<int>();
        var nameBytes = new List<byte[]>();
        int currentNameOffset = namesOffset;

        foreach (var import in imports)
        {
            byte[] dllNameBytes = Encoding.ASCII.GetBytes(import.DllName + "\0");
            nameOffsets.Add(currentNameOffset);
            nameBytes.Add(dllNameBytes);
            currentNameOffset += dllNameBytes.Length;
        }

        for (int i = 0; i < imports.Count; i++)
        {
            writer.Write((uint)0); // OriginalFirstThunk
            writer.Write((uint)0); // TimeDateStamp
            writer.Write((uint)0); // ForwarderChain
            writer.Write((uint)nameOffsets[i]); // Name RVA (placeholder)
            writer.Write((uint)0); // FirstThunk
        }

        writer.Write(new byte[20]); // null terminator descriptor

        foreach (var name in nameBytes)
        {
            writer.Write(name);
        }

        return ms.ToArray();
    }

    public List<ImportEntry> ParseImports(byte[] peBytes, uint importRva)
    {
        var imports = new List<ImportEntry>();
        if (importRva == 0) return imports;

        int offset = RvaToOffset(importRva);
        while (offset + 20 <= peBytes.Length)
        {
            uint nameRva = BitConverter.ToUInt32(peBytes, offset + 12);
            if (nameRva == 0) break;

            int nameOffset = RvaToOffset(nameRva);
            string dllName = ReadAsciiString(peBytes, nameOffset);

            uint thunkRva = BitConverter.ToUInt32(peBytes, offset + 16);
            var functions = ParseThunks(peBytes, thunkRva);

            imports.Add(new ImportEntry
            {
                DllName = dllName,
                Functions = functions
            });

            offset += 20;
        }

        return imports;
    }

    private List<string> ParseThunks(byte[] peBytes, uint thunkRva)
    {
        var functions = new List<string>();
        int offset = RvaToOffset(thunkRva);

        while (offset + 8 <= peBytes.Length)
        {
            long thunkData = BitConverter.ToInt64(peBytes, offset);
            if (thunkData == 0) break;

            if ((thunkData & (1L << 63)) == 0)
            {
                int hintOffset = RvaToOffset((uint)(thunkData & 0x7FFFFFFF)) + 2;
                functions.Add(ReadAsciiString(peBytes, hintOffset));
            }

            offset += 8;
        }

        return functions;
    }

    private int RvaToOffset(uint rva)
    {
        foreach (var section in _peData.Sections)
        {
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
            {
                return (int)(rva - section.VirtualAddress + section.PointerToRawData);
            }
        }
        return (int)rva;
    }

    private static string ReadAsciiString(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }
}
