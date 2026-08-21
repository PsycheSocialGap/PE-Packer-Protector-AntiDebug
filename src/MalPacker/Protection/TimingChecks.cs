namespace MalPacker.Protection;

using System.Diagnostics;
using System.Runtime.InteropServices;

public static class TimingChecks
{
    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceFrequency(out long lpFrequency);

    private const long RdtscThreshold = 500_000;
    private const int TickCountThreshold = 100;

    public static bool IsBeingTraced()
    {
        return CheckRdtscTiming()
            || CheckTickCountDelta()
            || CheckPerformanceCounter()
            || CheckStopwatchAnomaly();
    }

    private static bool CheckRdtscTiming()
    {
        long start = GetTimestamp();
        Thread.SpinWait(100);
        long end = GetTimestamp();

        return (end - start) > RdtscThreshold;
    }

    private static bool CheckTickCountDelta()
    {
        int start = Environment.TickCount;
        Thread.Sleep(10);
        int end = Environment.TickCount;
        int delta = end - start;

        return delta > TickCountThreshold;
    }

    private static bool CheckPerformanceCounter()
    {
        QueryPerformanceFrequency(out long frequency);
        QueryPerformanceCounter(out long start);

        double sum = 0;
        for (int i = 0; i < 1000; i++)
            sum += Math.Sqrt(i);

        QueryPerformanceCounter(out long end);

        double elapsed = (double)(end - start) / frequency * 1000;
        _ = sum;
        return elapsed > 50;
    }

    private static bool CheckStopwatchAnomaly()
    {
        var sw = Stopwatch.StartNew();
        int iterations = 0;

        while (sw.ElapsedMilliseconds < 5)
        {
            iterations++;
            Thread.SpinWait(10);
        }

        sw.Stop();
        return iterations < 10;
    }

    private static long GetTimestamp()
    {
        QueryPerformanceCounter(out long value);
        return value;
    }
}
