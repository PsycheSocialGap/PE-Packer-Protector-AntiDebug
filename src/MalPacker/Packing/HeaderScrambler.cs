namespace MalPacker.Packing;

using MalPacker.PE;

public static class HeaderScrambler
{
    public static void Scramble(PeData peData)
    {
        WipeDosStub(peData);
        RandomizeTimestamp(peData);
        NullifyDebugDirectory(peData);
        ScrambleRichHeader(peData);
    }

    private static void WipeDosStub(PeData peData)
    {
        int dosStubStart = 0x40;
        int peHeaderOffset = peData.PeHeaderOffset;

        if (peHeaderOffset > dosStubStart)
        {
            for (int i = dosStubStart; i < peHeaderOffset; i++)
            {
                peData.RawBytes[i] = (byte)Random.Shared.Next(256);
            }
        }
    }

    private static void RandomizeTimestamp(PeData peData)
    {
        int timestampOffset = peData.PeHeaderOffset + 8;
        byte[] randomTimestamp = BitConverter.GetBytes((uint)Random.Shared.Next());
        Buffer.BlockCopy(randomTimestamp, 0, peData.RawBytes, timestampOffset, 4);
    }

    private static void NullifyDebugDirectory(PeData peData)
    {
        int optionalHeaderOffset = peData.PeHeaderOffset + 24;
        int debugDirOffset = optionalHeaderOffset + (peData.Is64Bit ? 144 : 128);

        if (debugDirOffset + 8 <= peData.RawBytes.Length)
        {
            Array.Clear(peData.RawBytes, debugDirOffset, 8);
        }
    }

    private static void ScrambleRichHeader(PeData peData)
    {
        int richOffset = FindRichSignature(peData.RawBytes);
        if (richOffset < 0) return;

        int richStart = FindDanSSignature(peData.RawBytes, richOffset);
        if (richStart < 0) return;

        for (int i = richStart; i <= richOffset + 4; i++)
        {
            peData.RawBytes[i] = (byte)Random.Shared.Next(256);
        }
    }

    private static int FindRichSignature(byte[] data)
    {
        byte[] rich = "Rich"u8.ToArray();
        for (int i = 0x40; i < Math.Min(data.Length, 0x200); i++)
        {
            if (data[i] == rich[0] && data[i + 1] == rich[1] && data[i + 2] == rich[2] && data[i + 3] == rich[3])
                return i;
        }
        return -1;
    }

    private static int FindDanSSignature(byte[] data, int richOffset)
    {
        uint xorKey = BitConverter.ToUInt32(data, richOffset + 4);
        byte[] dans = [(byte)('D' ^ (xorKey & 0xFF)), (byte)('a' ^ ((xorKey >> 8) & 0xFF)),
                       (byte)('n' ^ ((xorKey >> 16) & 0xFF)), (byte)('S' ^ ((xorKey >> 24) & 0xFF))];

        for (int i = 0x40; i < richOffset; i++)
        {
            if (data[i] == dans[0] && data[i + 1] == dans[1] && data[i + 2] == dans[2] && data[i + 3] == dans[3])
                return i;
        }
        return 0x80;
    }
}
