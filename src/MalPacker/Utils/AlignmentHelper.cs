namespace MalPacker.Utils;

public static class AlignmentHelper
{
    public static uint AlignUp(uint value, uint alignment)
    {
        if (alignment == 0) return value;
        return (value + alignment - 1) & ~(alignment - 1);
    }

    public static ulong AlignUp(ulong value, ulong alignment)
    {
        if (alignment == 0) return value;
        return (value + alignment - 1) & ~(alignment - 1);
    }

    public static uint AlignDown(uint value, uint alignment)
    {
        if (alignment == 0) return value;
        return value & ~(alignment - 1);
    }

    public static bool IsAligned(uint value, uint alignment)
    {
        return alignment != 0 && (value & (alignment - 1)) == 0;
    }

    public static uint PaddingNeeded(uint value, uint alignment)
    {
        uint aligned = AlignUp(value, alignment);
        return aligned - value;
    }
}
