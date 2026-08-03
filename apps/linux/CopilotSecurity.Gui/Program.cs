using Avalonia;
using Avalonia.Fonts.Inter;
using Secwest.CopilotSecurity.Desktop;

namespace Secwest.CopilotSecurity.Gui.Linux;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Contains("--smoke-test", StringComparer.Ordinal))
        {
            return RunSmokeTest(Console.Out, Console.Error);
        }

        try
        {
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("Copilot Security GUI failed to start: " + exception.Message);
            return 1;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    public static int RunSmokeTest(TextWriter output, TextWriter error)
    {
        try
        {
            var options = DesktopPlatformOptions.Linux();
            if (options.NodeExecutableNames is not ["node"]
                || options.CopilotExecutableNames is not ["copilot"]
                || options.HistoryDirectoryName != "gui-linux-runs"
                || options.BenchmarkDirectoryName != "gui-linux-benchmarks"
                || !Path.IsPathRooted(options.SettingsPath))
            {
                throw new InvalidOperationException("Linux platform isolation defaults are invalid.");
            }
            output.WriteLine("Copilot Security Linux GUI smoke test passed.");
            output.WriteLine("Settings: " + options.SettingsPath);
            return 0;
        }
        catch (Exception exception)
        {
            error.WriteLine("Linux GUI smoke test failed: " + exception.Message);
            return 1;
        }
    }
}
