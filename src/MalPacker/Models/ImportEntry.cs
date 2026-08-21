namespace MalPacker.Models;

public sealed record ImportEntry
{
    public required string DllName { get; init; }
    public List<string> Functions { get; init; } = [];
    public uint FirstThunkRva { get; init; }
    public uint OriginalFirstThunkRva { get; init; }

    public override string ToString()
    {
        return $"{DllName} ({Functions.Count} functions)";
    }
}
