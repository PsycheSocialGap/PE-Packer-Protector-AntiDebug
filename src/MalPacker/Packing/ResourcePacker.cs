namespace MalPacker.Packing;

using MalPacker.PE;

public sealed class ResourcePacker
{
    private readonly PeData _peData;

    public ResourcePacker(PeData peData)
    {
        _peData = peData;
    }

    public byte[] PackResources()
    {
        var resourceSection = _peData.Sections.FirstOrDefault(s => s.Name == ".rsrc");
        if (resourceSection is null)
            return [];

        byte[] compressed = LzmaCompressor.Compress(resourceSection.RawData);
        return compressed;
    }

    public void EmbedPackedPayload(byte[] packedPayload, byte[] encryptionKey)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write((uint)0x504B4400); // magic "PKD\0"
        writer.Write((uint)packedPayload.Length);
        writer.Write((uint)encryptionKey.Length);
        writer.Write(encryptionKey);
        writer.Write(packedPayload);

        byte[] resourceData = ms.ToArray();

        var existingRsrc = _peData.Sections.FirstOrDefault(s => s.Name == ".rsrc");
        if (existingRsrc is not null)
        {
            existingRsrc.RawData = resourceData;
            existingRsrc.VirtualSize = (uint)resourceData.Length;
        }
    }

    public (byte[] Payload, byte[] Key)? ExtractPackedPayload(byte[] resourceData)
    {
        if (resourceData.Length < 12)
            return null;

        uint magic = BitConverter.ToUInt32(resourceData, 0);
        if (magic != 0x504B4400)
            return null;

        uint payloadSize = BitConverter.ToUInt32(resourceData, 4);
        uint keySize = BitConverter.ToUInt32(resourceData, 8);

        byte[] key = new byte[keySize];
        Buffer.BlockCopy(resourceData, 12, key, 0, (int)keySize);

        byte[] payload = new byte[payloadSize];
        Buffer.BlockCopy(resourceData, 12 + (int)keySize, payload, 0, (int)payloadSize);

        return (payload, key);
    }
}
