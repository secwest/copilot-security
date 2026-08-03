using Secwest.CopilotSecurity.Desktop;
using Secwest.CopilotSecurity.Desktop.ViewModels;

var tests = new (string Name, Action Run)[]
{
    ("Windows defaults retain the native application contract", WindowsDefaults),
    ("Linux defaults use isolated executable and state names", LinuxDefaults),
    ("shared view model honors platform-specific durable paths", SharedViewModelPaths),
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        test.Run();
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

static void SharedViewModelPaths()
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
        using (var viewModel = new MainViewModel(options))
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
        using (var restored = new MainViewModel(options))
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
