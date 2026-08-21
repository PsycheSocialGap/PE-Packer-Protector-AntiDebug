namespace MalPacker.PE;

using MalPacker.Utils;

public sealed class PeReader
{
    private readonly byte[] _data;

    public PeReader(byte[] data)
    {
        _data = data;
    }

    public PeData Parse()
    {
        if (_data.Length < 64 || _data[0] != 0x4D || _data[1] != 0x5A)
            throw new InvalidOperationException("Invalid PE file: bad MZ signature.");

        int peOffset = BitConverter.ToInt32(_data, 0x3C);
        if (peOffset + 24 >= _data.Length)
            throw new InvalidOperationException("Invalid PE offset.");

        ushort machine = BitConverter.ToUInt16(_data, peOffset + 4);
        bool is64 = machine == 0x8664;
        ushort numberOfSections = BitConverter.ToUInt16(_data, peOffset + 6);
        int optionalHeaderOffset = peOffset + 24;

        uint sizeOfImage = BitConverter.ToUInt32(_data, optionalHeaderOffset + 56);
        uint sizeOfHeaders = BitConverter.ToUInt32(_data, optionalHeaderOffset + 60);
        uint fileAlignment = BitConverter.ToUInt32(_data, optionalHeaderOffset + 36);
        uint sectionAlignment = BitConverter.ToUInt32(_data, optionalHeaderOffset + 32);
        uint entryPointRva = BitConverter.ToUInt32(_data, optionalHeaderOffset + 16);

        int sectionTableOffset = optionalHeaderOffset + (is64 ? 240 : 224);
        var sections = new List<PeSection>();

        for (int i = 0; i < numberOfSections; i++)
        {
            int off = sectionTableOffset + i * 40;
            string name = System.Text.Encoding.ASCII.GetString(_data, off, 8).TrimEnd('\0');
            uint virtualSize = BitConverter.ToUInt32(_data, off + 8);
            uint virtualAddr = BitConverter.ToUInt32(_data, off + 12);
            uint rawSize = BitConverter.ToUInt32(_data, off + 16);
            uint rawPtr = BitConverter.ToUInt32(_data, off + 20);
            uint characteristics = BitConverter.ToUInt32(_data, off + 36);

            byte[] sectionData = new byte[rawSize];
            if (rawPtr + rawSize <= _data.Length)
                Buffer.BlockCopy(_data, (int)rawPtr, sectionData, 0, (int)rawSize);

            sections.Add(new PeSection
            {
                Name = name,
                VirtualAddress = virtualAddr,
                VirtualSize = virtualSize,
                PointerToRawData = rawPtr,
                SizeOfRawData = rawSize,
                Characteristics = characteristics,
                RawData = sectionData
            });
        }

        return new PeData
        {
            RawBytes = (byte[])_data.Clone(),
            Is64Bit = is64,
            PeHeaderOffset = peOffset,
            EntryPointRva = entryPointRva,
            SizeOfImage = sizeOfImage,
            SizeOfHeaders = sizeOfHeaders,
            FileAlignment = fileAlignment,
            SectionAlignment = sectionAlignment,
            NumberOfSections = numberOfSections,
            Sections = sections
        };
    }
}
