namespace MalPacker.Utils;

public static class ChecksumCalc
{
    private static readonly uint[] Crc32Table = GenerateCrc32Table();

    public static uint CalculatePeChecksum(byte[] peBytes)
    {
        int checksumOffset = GetChecksumOffset(peBytes);
        long checksum = 0;
        int remainder = peBytes.Length % 4;

        for (int i = 0; i < peBytes.Length / 4; i++)
        {
            if (i * 4 == checksumOffset)
                continue;

            uint dword = BitConverter.ToUInt32(peBytes, i * 4);
            checksum += dword;
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }

        if (remainder > 0)
        {
            byte[] last = new byte[4];
            Buffer.BlockCopy(peBytes, peBytes.Length - remainder, last, 0, remainder);
            checksum += BitConverter.ToUInt32(last, 0);
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += (checksum >> 16);
        checksum &= 0xFFFF;
        checksum += (uint)peBytes.Length;

        return (uint)checksum;
    }

    public static uint Crc32(byte[] data, int offset, int length)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = offset; i < offset + length && i < data.Length; i++)
        {
            byte index = (byte)((crc ^ data[i]) & 0xFF);
            crc = (crc >> 8) ^ Crc32Table[index];
        }
        return crc ^ 0xFFFFFFFF;
    }

    private static int GetChecksumOffset(byte[] pe)
    {
        int peOffset = BitConverter.ToInt32(pe, 0x3C);
        return peOffset + 24 + 64;
    }

    private static uint[] GenerateCrc32Table()
    {
        uint[] table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
            table[i] = crc;
        }
        return table;
    }
}
