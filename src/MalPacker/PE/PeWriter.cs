namespace MalPacker.PE;

using MalPacker.Utils;

public sealed class PeWriter
{
    private readonly PeData _peData;

    public PeWriter(PeData peData)
    {
        _peData = peData;
    }

    public byte[] Build()
    {
        uint totalSize = CalculateTotalSize();
        byte[] output = new byte[totalSize];

        uint headersSize = AlignmentHelper.AlignUp(_peData.SizeOfHeaders, _peData.FileAlignment);
        Buffer.BlockCopy(_peData.RawBytes, 0, output, 0, (int)Math.Min(headersSize, _peData.RawBytes.Length));

        UpdateNumberOfSections(output);
        UpdateSizeOfImage(output);

        WriteSectionTable(output);

        foreach (var section in _peData.Sections)
        {
            if (section.PointerToRawData + section.RawData.Length <= output.Length)
            {
                Buffer.BlockCopy(section.RawData, 0, output, (int)section.PointerToRawData, section.RawData.Length);
            }
        }

        UpdateChecksum(output);
        return output;
    }

    private uint CalculateTotalSize()
    {
        uint maxEnd = _peData.SizeOfHeaders;
        foreach (var section in _peData.Sections)
        {
            uint sectionEnd = section.PointerToRawData + AlignmentHelper.AlignUp((uint)section.RawData.Length, _peData.FileAlignment);
            if (sectionEnd > maxEnd)
                maxEnd = sectionEnd;
        }
        return maxEnd;
    }

    private void UpdateNumberOfSections(byte[] output)
    {
        int offset = _peData.PeHeaderOffset + 6;
        BitConverter.GetBytes((ushort)_peData.Sections.Count).CopyTo(output, offset);
    }

    private void UpdateSizeOfImage(byte[] output)
    {
        uint newSizeOfImage = 0;
        foreach (var section in _peData.Sections)
        {
            uint sectionEnd = section.VirtualAddress + AlignmentHelper.AlignUp(section.VirtualSize, _peData.SectionAlignment);
            if (sectionEnd > newSizeOfImage)
                newSizeOfImage = sectionEnd;
        }

        int offset = _peData.PeHeaderOffset + 24 + 56;
        BitConverter.GetBytes(newSizeOfImage).CopyTo(output, offset);
    }

    private void WriteSectionTable(byte[] output)
    {
        int sectionTableOffset = _peData.PeHeaderOffset + 24 + (_peData.Is64Bit ? 240 : 224);

        for (int i = 0; i < _peData.Sections.Count; i++)
        {
            var section = _peData.Sections[i];
            int offset = sectionTableOffset + i * 40;

            byte[] nameBytes = new byte[8];
            System.Text.Encoding.ASCII.GetBytes(section.Name).CopyTo(nameBytes, 0);
            Buffer.BlockCopy(nameBytes, 0, output, offset, 8);

            BitConverter.GetBytes(section.VirtualSize).CopyTo(output, offset + 8);
            BitConverter.GetBytes(section.VirtualAddress).CopyTo(output, offset + 12);
            BitConverter.GetBytes(section.SizeOfRawData).CopyTo(output, offset + 16);
            BitConverter.GetBytes(section.PointerToRawData).CopyTo(output, offset + 20);
            BitConverter.GetBytes(section.Characteristics).CopyTo(output, offset + 36);
        }
    }

    private void UpdateChecksum(byte[] output)
    {
        uint checksum = ChecksumCalc.CalculatePeChecksum(output);
        int checksumOffset = _peData.PeHeaderOffset + 24 + 64;
        BitConverter.GetBytes(checksum).CopyTo(output, checksumOffset);
    }
}
