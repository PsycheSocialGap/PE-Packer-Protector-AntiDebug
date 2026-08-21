namespace MalPacker.Stub;

using MalPacker.Packing;

public sealed class DecompressorStub
{
    private readonly byte[] _compressedData;
    private readonly int _originalSize;

    public DecompressorStub(byte[] compressedData, int originalSize)
    {
        _compressedData = compressedData;
        _originalSize = originalSize;
    }

    public byte[] Decompress()
    {
        byte[] result = LzmaCompressor.Decompress(_compressedData);

        if (result.Length != _originalSize)
            throw new InvalidOperationException(
                $"Decompression size mismatch: expected {_originalSize}, got {result.Length}");

        return result;
    }

    public static byte[] CreateSelfExtractingPayload(byte[] originalData)
    {
        byte[] compressed = LzmaCompressor.Compress(originalData);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write((uint)0x44435058); // "XPCD" magic
        writer.Write((uint)originalData.Length);
        writer.Write((uint)compressed.Length);
        writer.Write(compressed);

        return ms.ToArray();
    }

    public static byte[]? ExtractPayload(byte[] selfExtractingData)
    {
        if (selfExtractingData.Length < 12)
            return null;

        uint magic = BitConverter.ToUInt32(selfExtractingData, 0);
        if (magic != 0x44435058)
            return null;

        uint originalSize = BitConverter.ToUInt32(selfExtractingData, 4);
        uint compressedSize = BitConverter.ToUInt32(selfExtractingData, 8);

        byte[] compressed = new byte[compressedSize];
        Buffer.BlockCopy(selfExtractingData, 12, compressed, 0, (int)compressedSize);

        var stub = new DecompressorStub(compressed, (int)originalSize);
        return stub.Decompress();
    }
}
