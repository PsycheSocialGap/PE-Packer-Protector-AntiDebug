namespace MalPacker.Models;

public sealed record PeSectionInfo
{
    public required string Name { get; init; }
    public required uint VirtualAddress { get; init; }
    public required uint VirtualSize { get; init; }
    public required uint RawDataPointer { get; init; }
    public required uint RawDataSize { get; init; }
    public required uint Characteristics { get; init; }
    public double Entropy { get; init; }
    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
    public bool IsReadable => (Characteristics & 0x40000000) != 0;

    public static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        int[] frequency = new int[256];
        foreach (byte b in data)
            frequency[b]++;

        double entropy = 0;
        double length = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequency[i] == 0) continue;
            double probability = frequency[i] / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
