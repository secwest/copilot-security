namespace Secwest.CopilotSecurity.Desktop;

public sealed record DesktopPlatformOptions(
    string SettingsPath,
    IReadOnlyList<string> NodeExecutableNames,
    IReadOnlyList<string> CopilotExecutableNames,
    string HistoryDirectoryName,
    string BenchmarkDirectoryName,
    StringComparer PathComparer)
{
    public static DesktopPlatformOptions Current() =>
        OperatingSystem.IsWindows() ? Windows() : Linux();

    public static DesktopPlatformOptions Windows()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new DesktopPlatformOptions(
            Path.Combine(local, "Secwest", "CopilotSecurity", "gui", "settings.json"),
            ["node.exe"],
            ["copilot.exe", "copilot.cmd"],
            "gui-runs",
            "gui-benchmarks",
            StringComparer.OrdinalIgnoreCase);
    }

    public static DesktopPlatformOptions Linux()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var configured = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        var configRoot = !string.IsNullOrWhiteSpace(configured) && Path.IsPathRooted(configured)
            ? configured
            : Path.Combine(profile, ".config");
        return new DesktopPlatformOptions(
            Path.Combine(configRoot, "secwest", "copilot-security", "gui-linux", "settings.json"),
            ["node"],
            ["copilot"],
            "gui-linux-runs",
            "gui-linux-benchmarks",
            StringComparer.Ordinal);
    }
}
