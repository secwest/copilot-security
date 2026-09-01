using Secwest.CopilotSecurity.Desktop;
using Secwest.CopilotSecurity.Desktop.ViewModels;
using Secwest.CopilotSecurity.Core.Models;
using Secwest.CopilotSecurity.Core.Services;

var tests = new (string Name, Func<Task> Run)[]
{
    ("Windows defaults retain the native application contract", () => RunSync(WindowsDefaults)),
    ("Linux defaults use isolated executable and state names", () => RunSync(LinuxDefaults)),
    ("shared view model honors platform-specific durable paths", SharedViewModelPaths),
    ("shared view model awaits scanner termination during shutdown", ShutdownAwaitsScannerTermination),
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine("PASS " + test.Name);
    }
    catch (Exception exception)
    {
        failures.Add(test.Name + ": " + exception);
        Console.Error.WriteLine("FAIL " + test.Name + Environment.NewLine + exception);
    }
}

Console.WriteLine($"{tests.Length - failures.Count}/{tests.Length} tests passed");
return failures.Count == 0 ? 0 : 1;

static Task RunSync(Action action)
{
    action();
    return Task.CompletedTask;
}

static void WindowsDefaults()
{
    var options = DesktopPlatformOptions.Windows();
    Assert.Equal("node.exe", options.NodeExecutableNames.Single());
    Assert.SequenceEqual(["copilot.exe", "copilot.cmd"], options.CopilotExecutableNames);
    Assert.Equal("gui-runs", options.HistoryDirectoryName);
    Assert.Equal("gui-benchmarks", options.BenchmarkDirectoryName);
    Assert.True(options.SettingsPath.EndsWith(
        Path.Combine("Secwest", "CopilotSecurity", "gui", "settings.json"),
        StringComparison.OrdinalIgnoreCase));
    Assert.True(options.PathComparer.Equals("A", "a"));
}

static void LinuxDefaults()
{
    var options = DesktopPlatformOptions.Linux();
    Assert.Equal("node", options.NodeExecutableNames.Single());
    Assert.Equal("copilot", options.CopilotExecutableNames.Single());
    Assert.Equal("gui-linux-runs", options.HistoryDirectoryName);
    Assert.Equal("gui-linux-benchmarks", options.BenchmarkDirectoryName);
    Assert.True(options.SettingsPath.EndsWith(
        Path.Combine("secwest", "copilot-security", "gui-linux", "settings.json"),
        StringComparison.Ordinal));
    Assert.False(options.PathComparer.Equals("A", "a"));
}

static async Task SharedViewModelPaths()
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "copilot-security-desktop-tests-" + Guid.NewGuid().ToString("N"));
    var settings = Path.Combine(root, "preferences", "settings.json");
    var state = Path.Combine(root, "state");
    try
    {
        var options = new DesktopPlatformOptions(
            settings,
            ["missing-node"],
            ["missing-copilot"],
            "isolated-history",
            "isolated-benchmarks",
            StringComparer.Ordinal);
        await using (var viewModel = new MainViewModel(options))
        {
            viewModel.StateRoot = state;
            viewModel.RepositoryPath = root;
            Assert.Equal(Path.Combine(state, "copilot-security-home"), viewModel.RuntimeHome);
            Assert.Equal(
                Path.Combine(state, "copilot-security-home", "isolated-history"),
                viewModel.HistoryRoot);
            Assert.Equal(
                Path.Combine(state, "copilot-security-home", "isolated-benchmarks"),
                viewModel.BenchmarkResultsDirectory);
            Assert.Equal(string.Empty, viewModel.NodePath);
            Assert.Equal(string.Empty, viewModel.CopilotPath);
        }

        Assert.True(File.Exists(settings));
        await using (var restored = new MainViewModel(options))
        {
            Assert.Equal(state, restored.StateRoot);
            Assert.Equal(root, restored.RepositoryPath);
        }
    }
    finally
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

static async Task ShutdownAwaitsScannerTermination()
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "copilot-security-shutdown-tests-" + Guid.NewGuid().ToString("N"));
    var repository = Path.Combine(root, "repository");
    var scanner = Path.Combine(root, "copilot-security.mjs");
    Directory.CreateDirectory(repository);
    await File.WriteAllTextAsync(scanner, "// inert scanner fixture\n");
    var options = new DesktopPlatformOptions(
        Path.Combine(root, "preferences", "settings.json"),
        ["missing-node"],
        ["missing-copilot"],
        "isolated-history",
        "isolated-benchmarks",
        StringComparer.Ordinal);
    var runner = new ControlledScannerProcessRunner();
    try
    {
        await using var viewModel = new MainViewModel(options, runner)
        {
            StateRoot = Path.Combine(root, "state"),
            RepositoryPath = repository,
            NodePath = Environment.ProcessPath!,
            ScannerEntryPoint = scanner,
            CopilotPath = Environment.ProcessPath!,
        };
        viewModel.StartScanCommand.Execute(null);
        await runner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var shutdown = viewModel.DisposeAsync().AsTask();
        var concurrentShutdown = viewModel.DisposeAsync().AsTask();
        await runner.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(shutdown.IsCompleted);
        Assert.False(concurrentShutdown.IsCompleted);

        runner.AllowTermination.TrySetResult();
        await Task.WhenAll(shutdown, concurrentShutdown)
            .WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(runner.Completed);
    }
    finally
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

sealed class ControlledScannerProcessRunner : IScannerProcessRunner
{
    public TaskCompletionSource Started { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource CancellationObserved { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource AllowTermination { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    public bool Completed { get; private set; }

    public async Task<ScannerProcessResult> RunAsync(
        ScannerInvocation invocation,
        IProgress<ScannerProgress>? progress,
        CancellationToken cancellationToken)
    {
        Started.TrySetResult();
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            CancellationObserved.TrySetResult();
        }
        await AllowTermination.Task;
        Completed = true;
        return new ScannerProcessResult(
            ScanRunState.Canceled,
            null,
            TimeSpan.Zero,
            string.Empty,
            string.Empty,
            "Canceled by shutdown test.");
    }
}

static class Assert
{
    public static void True(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Expected true.");
    }

    public static void False(bool condition) => True(!condition);

    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', received '{actual}'.");
        }
    }

    public static void SequenceEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException("Sequences differ.");
        }
    }
}
