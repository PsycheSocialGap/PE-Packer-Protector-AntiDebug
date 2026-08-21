namespace MalPacker.Protection;

using System.Security.Cryptography;
using MalPacker.Utils;

public sealed class AntiTamper
{
    private readonly byte[] _originalHash;
    private readonly string _filePath;

    public AntiTamper(string filePath)
    {
        _filePath = filePath;
        _originalHash = ComputeFileHash(filePath);
    }

    public bool VerifyIntegrity()
    {
        byte[] currentHash = ComputeFileHash(_filePath);
        return CryptographicOperations.FixedTimeEquals(_originalHash, currentHash);
    }

    public static uint ComputeChecksum(byte[] data, int offset, int length)
    {
        return ChecksumCalc.Crc32(data, offset, length);
    }

    public static bool VerifySectionIntegrity(byte[] sectionData, uint expectedChecksum)
    {
        uint actual = ChecksumCalc.Crc32(sectionData, 0, sectionData.Length);
        return actual == expectedChecksum;
    }

    public static byte[] GenerateIntegrityStub(uint[] sectionChecksums)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write((uint)sectionChecksums.Length);
        foreach (uint checksum in sectionChecksums)
        {
            writer.Write(checksum);
        }

        return ms.ToArray();
    }

    private static byte[] ComputeFileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }
}
