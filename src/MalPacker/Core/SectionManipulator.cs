namespace MalPacker.Core;

using MalPacker.Models;
using MalPacker.PE;
using MalPacker.Utils;

public sealed class SectionManipulator
{
    private readonly PeData _peData;

    public SectionManipulator(PeData peData)
    {
        _peData = peData;
    }

    public void InjectAntiDebugStub()
    {
        byte[] stub =
        [
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
            0x0F, 0xB6, 0x40, 0x02,                                 // movzx eax, byte [rax+2]
            0x85, 0xC0,                                              // test eax, eax
            0x74, 0x05,                                              // jz +5
            0xB8, 0x01, 0x00, 0x00, 0x00,                           // mov eax, 1
            0xC3,                                                    // ret
            0x33, 0xC0,                                              // xor eax, eax
            0xC3                                                     // ret
        ];

        AddSection(".dbg", stub, 0x60000020);
    }

    public void InjectAntiDumpStub()
    {
        byte[] stub =
        [
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
            0x48, 0x8B, 0x40, 0x10,                                 // mov rax, [rax+0x10]
            0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,                    // mov dword [rax], 0
            0xC3                                                     // ret
        ];

        AddSection(".admp", stub, 0x60000020);
    }

    public void InjectIntegrityCheck()
    {
        uint checksum = ChecksumCalc.CalculatePeChecksum(_peData.RawBytes);
        byte[] checksumBytes = BitConverter.GetBytes(checksum);

        byte[] stub = new byte[32];
        stub[0] = 0xB8; // mov eax, <checksum>
        Buffer.BlockCopy(checksumBytes, 0, stub, 1, 4);
        stub[5] = 0xC3; // ret

        AddSection(".chk", stub, 0x40000040);
    }

    private void AddSection(string name, byte[] data, uint characteristics)
    {
        uint alignedSize = AlignmentHelper.AlignUp((uint)data.Length, _peData.FileAlignment);
        byte[] alignedData = new byte[alignedSize];
        Buffer.BlockCopy(data, 0, alignedData, 0, data.Length);

        uint lastSectionEnd = 0;
        uint lastVirtualEnd = 0;

        if (_peData.Sections.Count > 0)
        {
            var last = _peData.Sections[^1];
            lastSectionEnd = last.PointerToRawData + AlignmentHelper.AlignUp((uint)last.RawData.Length, _peData.FileAlignment);
            lastVirtualEnd = last.VirtualAddress + AlignmentHelper.AlignUp(last.VirtualSize, _peData.SectionAlignment);
        }

        _peData.Sections.Add(new PeSection
        {
            Name = name,
            VirtualAddress = lastVirtualEnd,
            VirtualSize = (uint)data.Length,
            PointerToRawData = lastSectionEnd,
            SizeOfRawData = alignedSize,
            Characteristics = characteristics,
            RawData = alignedData
        });
    }
}
