using System.Diagnostics;

namespace Secwest.Benchmarks.Services;

public sealed class CommandRunner
{
    public Process? Run(string command)
    {
        var start = new ProcessStartInfo("cmd.exe", "/c " + command);
        return Process.Start(start);
    }
}
