namespace MalPacker.Config;

public sealed class PackerConfig
{
    public string InputPath { get; init; } = string.Empty;
    public string OutputPath { get; init; } = string.Empty;
    public bool EnableCompression { get; init; }
    public bool EnableEncryption { get; init; }
    public bool EnableAntiDebug { get; init; }
    public bool EnableAntiDump { get; init; }
    public bool EnableAntiTamper { get; init; }
    public bool ScrambleHeaders { get; init; }
    public CompressionLevel Compression { get; init; } = CompressionLevel.Normal;

    public static PackerConfig Parse(string[] args)
    {
        string input = args[0];
        string output = Path.ChangeExtension(input, ".packed.exe");
        bool compress = false, encrypt = false, antidebug = false;
        bool antidump = false, antitamper = false, scramble = false;

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--output" when i + 1 < args.Length:
                    output = args[++i];
                    break;
                case "--compress": compress = true; break;
                case "--encrypt": encrypt = true; break;
                case "--antidebug": antidebug = true; break;
                case "--antidump": antidump = true; break;
                case "--antitamper": antitamper = true; break;
                case "--scramble": scramble = true; break;
                case "--all":
                    compress = encrypt = antidebug = antidump = antitamper = scramble = true;
                    break;
            }
        }

        return new PackerConfig
        {
            InputPath = input,
            OutputPath = output,
            EnableCompression = compress,
            EnableEncryption = encrypt,
            EnableAntiDebug = antidebug,
            EnableAntiDump = antidump,
            EnableAntiTamper = antitamper,
            ScrambleHeaders = scramble
        };
    }
}

public enum CompressionLevel
{
    Fast,
    Normal,
    Maximum
}
