namespace MalPacker.Core;

using MalPacker.Config;
using MalPacker.Packing;
using MalPacker.PE;
using MalPacker.Protection;

public sealed class PackerEngine
{
    private readonly PackerConfig _config;

    public PackerEngine(PackerConfig config)
    {
        _config = config;
    }

    public async Task PackAsync()
    {
        if (!File.Exists(_config.InputPath))
            throw new FileNotFoundException($"Input file not found: {_config.InputPath}");

        byte[] inputPe = await File.ReadAllBytesAsync(_config.InputPath);
        Console.WriteLine($"[*] Input size: {inputPe.Length} bytes");

        var reader = new PeReader(inputPe);
        var peData = reader.Parse();
        Console.WriteLine($"[*] Sections: {peData.Sections.Count}, Architecture: {(peData.Is64Bit ? "x64" : "x86")}");

        var manipulator = new SectionManipulator(peData);

        if (_config.EnableCompression)
        {
            foreach (var section in peData.Sections)
            {
                byte[] compressed = LzmaCompressor.Compress(section.RawData);
                float ratio = (float)compressed.Length / section.RawData.Length * 100;
                Console.WriteLine($"[*] Compressed {section.Name}: {ratio:F1}%");
                section.RawData = compressed;
                section.IsCompressed = true;
            }
        }

        if (_config.EnableEncryption)
        {
            var encryptor = new SectionEncryptor();
            foreach (var section in peData.Sections.Where(s => s.Name != ".rsrc"))
            {
                section.RawData = encryptor.EncryptSection(section.RawData, out byte[] key);
                section.EncryptionKey = key;
                section.IsEncrypted = true;
                Console.WriteLine($"[*] Encrypted section: {section.Name}");
            }
        }

        if (_config.ScrambleHeaders)
        {
            HeaderScrambler.Scramble(peData);
            Console.WriteLine("[*] Headers scrambled");
        }

        if (_config.EnableAntiDebug)
            manipulator.InjectAntiDebugStub();

        if (_config.EnableAntiDump)
            manipulator.InjectAntiDumpStub();

        if (_config.EnableAntiTamper)
            manipulator.InjectIntegrityCheck();

        var writer = new PeWriter(peData);
        byte[] output = writer.Build();

        await File.WriteAllBytesAsync(_config.OutputPath, output);
        Console.WriteLine($"[+] Output: {_config.OutputPath} ({output.Length} bytes)");
    }
}
