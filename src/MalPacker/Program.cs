namespace MalPacker;

using MalPacker.Config;
using MalPacker.Core;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine("╔══════════════════════════════════╗");
        Console.WriteLine("║     MalPacker v2.0 - PE Packer  ║");
        Console.WriteLine("╚══════════════════════════════════╝");
        Console.WriteLine();

        if (args.Length < 1)
        {
            PrintUsage();
            return 1;
        }

        var config = PackerConfig.Parse(args);
        var engine = new PackerEngine(config);

        try
        {
            await engine.PackAsync();
            Console.WriteLine("[+] Packing complete.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] Error: {ex.Message}");
            return -1;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: MalPacker.exe <input.exe> [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --output <path>       Output file path");
        Console.WriteLine("  --compress            Enable LZMA compression");
        Console.WriteLine("  --encrypt             Encrypt sections with AES");
        Console.WriteLine("  --antidebug           Add anti-debugging protection");
        Console.WriteLine("  --antidump            Add anti-dump protection");
        Console.WriteLine("  --antitamper          Add integrity verification");
        Console.WriteLine("  --scramble            Scramble PE headers");
        Console.WriteLine("  --all                 Enable all protections");
    }
}
