using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using Secwest.CopilotSecurity.Desktop;
using Secwest.CopilotSecurity.Gui.Linux;

var failures = new List<string>();
Run("non-graphical application smoke contract", TestProgramSmoke);
Run("headless Linux window loads the scanner surface and exits UI smoke", TestHeadlessWindow);
Console.WriteLine($"{2 - failures.Count}/2 tests passed");
return failures.Count == 0 ? 0 : 1;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine("PASS " + name);
    }
    catch (Exception exception)
    {
        failures.Add(name + ": " + exception);
        Console.Error.WriteLine("FAIL " + name + Environment.NewLine + exception);
    }
}

static void TestProgramSmoke()
{
    using var output = new StringWriter();
    using var error = new StringWriter();
    Assert.Equal(0, Secwest.CopilotSecurity.Gui.Linux.Program.RunSmokeTest(output, error));
    Assert.Contains("smoke test passed", output.ToString());
    Assert.Equal(string.Empty, error.ToString());
}

static void TestHeadlessWindow()
{
    _ = AppBuilder.Configure<App>()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions())
        .SetupWithoutStarting();

    var root = Path.Combine(Path.GetTempPath(), "copilot-security-linux-ui-tests-" + Guid.NewGuid().ToString("N"));
    try
    {
        var platform = new DesktopPlatformOptions(
            Path.Combine(root, "config", "settings.json"),
            ["missing-node"],
            ["missing-copilot"],
            "gui-linux-runs",
            "gui-linux-benchmarks",
            StringComparer.Ordinal);
        var window = new MainWindow(platform);
        window.ViewModel.StateRoot = Path.Combine(root, "state");
        window.Show();
        Dispatcher.UIThread.RunJobs();

        Assert.Equal("Copilot Security", window.Title);
        Assert.True(window.FindControl<TabControl>("MainTabs")?.ItemCount >= 7);
        Assert.NotNull(window.FindControl<TextBox>("RepositoryPathBox"));
        Assert.NotNull(window.FindControl<DataGrid>("ProgressGrid"));
        Assert.NotNull(window.FindControl<DataGrid>("FindingsGrid"));
        Assert.NotNull(window.FindControl<TextBox>("ReportBox"));
        Assert.NotNull(window.FindControl<DataGrid>("HistoryGrid"));
        Assert.NotNull(window.FindControl<ListBox>("DiagnosticsList"));
        Assert.NotNull(window.FindControl<Button>("StartScanButton"));
        Assert.NotNull(window.FindControl<Button>("CancelButton"));
        Assert.True(window.ViewModel.RuntimeHome.EndsWith(
            Path.Combine("state", "copilot-security-home"),
            StringComparison.Ordinal));
        Assert.True(window.ViewModel.HistoryRoot.EndsWith(
            Path.Combine("copilot-security-home", "gui-linux-runs"),
            StringComparison.Ordinal));

        window.Close();
        Dispatcher.UIThread.RunJobs();

        var shutdownRequested = false;
        using var fallbackRequested = new ManualResetEventSlim();
        var smokeWindow = new MainWindow(platform);
        App.ConfigureUiSmokeShutdown(
            smokeWindow,
            () => shutdownRequested = true,
            fallbackRequested.Set,
            TimeSpan.FromMilliseconds(25));
        smokeWindow.Show();
        Dispatcher.UIThread.RunJobs();
        Assert.True(shutdownRequested);
        Assert.False(smokeWindow.IsVisible);
        Assert.True(fallbackRequested.Wait(TimeSpan.FromSeconds(1)));
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

static class Assert
{
    public static void True(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Expected true.");
    }

    public static void False(bool condition)
    {
        if (condition) throw new InvalidOperationException("Expected false.");
    }

    public static void NotNull(object? value)
    {
        if (value is null) throw new InvalidOperationException("Expected a non-null value.");
    }

    public static void Contains(string expected, string actual)
    {
        if (!actual.Contains(expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Expected '{actual}' to contain '{expected}'.");
        }
    }

    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', received '{actual}'.");
        }
    }
}
