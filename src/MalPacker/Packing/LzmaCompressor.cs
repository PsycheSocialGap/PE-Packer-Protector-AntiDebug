namespace MalPacker.Packing;

using System.IO.Compression;

public static class LzmaCompressor
{
    public static byte[] Compress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var brotli = new BrotliStream(output, System.IO.Compression.CompressionLevel.SmallestSize))
        {
            brotli.Write(data, 0, data.Length);
        }

        byte[] compressed = output.ToArray();
        byte[] result = new byte[compressed.Length + 4];
        BitConverter.GetBytes(data.Length).CopyTo(result, 0);
        Buffer.BlockCopy(compressed, 0, result, 4, compressed.Length);

        return result;
    }

    public static byte[] Decompress(byte[] compressedData)
    {
        int originalSize = BitConverter.ToInt32(compressedData, 0);
        byte[] result = new byte[originalSize];

        using var input = new MemoryStream(compressedData, 4, compressedData.Length - 4);
        using var brotli = new BrotliStream(input, CompressionMode.Decompress);

        int totalRead = 0;
        while (totalRead < originalSize)
        {
            int read = brotli.Read(result, totalRead, originalSize - totalRead);
            if (read == 0) break;
            totalRead += read;
        }

        return result;
    }

    public static float GetCompressionRatio(byte[] original, byte[] compressed)
    {
        return (float)compressed.Length / original.Length;
    }
}
