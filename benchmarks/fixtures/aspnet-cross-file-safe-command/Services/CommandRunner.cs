using System.Diagnostics;

namespace Secwest.Benchmarks.Services;

public sealed class CommandRunner
{
    public Process? Ping(string host)
    {
        var start = new ProcessStartInfo("ping.exe")
        {
            UseShellExecute = false,
        };
        start.ArgumentList.Add("-n");
        start.ArgumentList.Add("1");
        start.ArgumentList.Add(host);
        return Process.Start(start);
    }
}
