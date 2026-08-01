using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Secwest.CopilotSecurity.Core.Models;
using Secwest.CopilotSecurity.Core.Services;

var tests = new (string Name, Func<Task> Run)[]
{
    ("scan command uses an argument list and private state", TestScanCommandAsync),
    ("scan command rejects overlaps and invalid deep diff", TestScanCommandRejectionsAsync),
    ("scanner discovery ignores the process working directory", TestInstallationDiscoveryAsync),
    ("artifact reader accepts sealed structure and rejects partial output", TestArtifactReaderAsync),
    ("benchmark comparison catches metric and case regressions", TestComparisonAsync),
    ("GUI settings persist atomically without credentials", TestSettingsAsync),
    ("process runner captures progress and cancels the process tree", TestProcessRunnerAsync),
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

static Task TestScanCommandAsync()
{
    using var fixture = new TemporaryFixture();
    var repository = fixture.Directory("repository");
    var include = fixture.File(Path.Combine("repository", "scope & literal", "entry.ts"), "export {};\n");
    var output = Path.Combine(fixture.Root, "results");
    var installation = fixture.Installation();
    var request = new ScanRequest
    {
        RepositoryPath = repository,
        OutputDirectory = output,
        Mode = ScanMode.Standard,
        IncludePaths = [include],
        MaximumAiCredits = null,
    };

    var invocation = new ScannerCommandBuilder().BuildScan(installation, request);
    Assert.Equal(Path.GetFullPath(installation.NodeExecutable), invocation.FileName);
    Assert.True(invocation.Arguments.Contains("scope & literal/entry.ts"), "Scoped path must remain one literal argument.");
    Assert.False(invocation.Arguments.Any(argument => argument.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase)), "No shell may be introduced.");
    Assert.Equal(Path.GetFullPath(installation.StateRoot), invocation.Environment["COPILOT_SECURITY_HOME"]);
    Assert.Equal(Path.GetFullPath(installation.CopilotExecutable), invocation.Environment["COPILOT_CLI_PATH"]);
    Assert.Equal(
        Path.Combine(Path.GetFullPath(installation.StateRoot), "copilot-security-home"),
        installation.RuntimeHome);
    Assert.False(invocation.Arguments.Contains("--max-ai-credits"), "No implicit account credit ceiling may be added.");
    return Task.CompletedTask;
}

static Task TestScanCommandRejectionsAsync()
{
    using var fixture = new TemporaryFixture();
    var repository = fixture.Directory("repository");
    var installation = fixture.Installation();
    var builder = new ScannerCommandBuilder();
    Assert.Throws<ArgumentException>(() => builder.BuildScan(
        installation,
        new ScanRequest
        {
            RepositoryPath = repository,
            OutputDirectory = Path.Combine(repository, "results"),
            Mode = ScanMode.Standard,
        }));
    Assert.Throws<ArgumentException>(() => builder.BuildScan(
        installation,
        new ScanRequest
        {
            RepositoryPath = repository,
            OutputDirectory = Path.Combine(fixture.Root, "results"),
            Mode = ScanMode.Deep,
            TargetKind = ScanTargetKind.CommittedDiff,
            BaseRevision = "main",
        }));
    var repositoryEntryPoint = fixture.File(
        Path.Combine("repository", "sdk", "typescript", "bin", "copilot-security.mjs"));
    var repositoryInstallation = installation with
    {
        ScannerEntryPoint = repositoryEntryPoint,
    };
    Assert.Throws<ArgumentException>(() => builder.BuildScan(
        repositoryInstallation,
        new ScanRequest
        {
            RepositoryPath = repository,
            OutputDirectory = Path.Combine(fixture.Root, "separate-results"),
            Mode = ScanMode.Standard,
        }));
    return Task.CompletedTask;
}

static Task TestInstallationDiscoveryAsync()
{
    using var fixture = new TemporaryFixture();
    var applicationBase = fixture.Directory(Path.Combine("installed", "apps", "gui"));
    var installed = fixture.File(
        Path.Combine("installed", "sdk", "typescript", "bin", "copilot-security.mjs"),
        "installed\n");
    var attackerDirectory = fixture.Directory("attacker");
    _ = fixture.File(
        Path.Combine("attacker", "sdk", "typescript", "bin", "copilot-security.mjs"),
        "attacker\n");
    var originalDirectory = Environment.CurrentDirectory;
    try
    {
        Environment.CurrentDirectory = attackerDirectory;
        var discovered = ScannerInstallationDiscovery.FindInstalledFile(
            applicationBase,
            "sdk",
            "typescript",
            "bin",
            "copilot-security.mjs");
        Assert.Equal(Path.GetFullPath(installed), discovered);

        File.Delete(installed);
        Assert.Equal<string?>(null, ScannerInstallationDiscovery.FindInstalledFile(
            applicationBase,
            "sdk",
            "typescript",
            "bin",
            "copilot-security.mjs"));
    }
    finally
    {
        Environment.CurrentDirectory = originalDirectory;
    }
    return Task.CompletedTask;
}

static async Task TestArtifactReaderAsync()
{
    using var fixture = new TemporaryFixture();
    var scan = fixture.Directory("scan");
    await File.WriteAllTextAsync(Path.Combine(scan, "report.md"), "# Report\n");
    await File.WriteAllTextAsync(Path.Combine(scan, "coverage.json"), """
        {"documentType":"copilot-security.coverage","completeness":"complete"}
        """);
    await File.WriteAllTextAsync(Path.Combine(scan, "findings.json"), """
        {"documentType":"copilot-security.findings","findings":[{"findingId":"F-1","title":"Injection","summary":"Input reaches a sink.","taxonomy":{"category":"injection","cwe":["CWE-78"]},"severity":{"level":"high"},"confidence":{"level":"high"},"locations":[{"path":"src/app.js","startLine":4,"endLine":5,"role":"sink"}],"validation":{"summary":"A deterministic witness executed the sink."},"attackPath":{"summary":"HTTP input reaches the shell."},"remediation":"Avoid the shell."}]}
        """);
    var findingsDigest = await HashPathAsync(Path.Combine(scan, "findings.json"));
    var coverageDigest = await HashPathAsync(Path.Combine(scan, "coverage.json"));
    await File.WriteAllTextAsync(
        Path.Combine(scan, "scan-manifest.json"),
        JsonSerializer.Serialize(new
        {
            documentType = "copilot-security.scan-manifest",
            scan = new
            {
                id = "scan-1",
                status = "complete",
                startedAt = "2026-07-31T00:00:00Z",
                completedAt = "2026-07-31T00:05:00Z",
                target = new { displayName = "fixture" },
                artifacts = new[]
                {
                    new { path = "findings.json", sha256 = findingsDigest },
                    new { path = "coverage.json", sha256 = coverageDigest },
                },
            },
        }));

    var reader = new ScanArtifactReader();
    var artifacts = await reader.ReadAsync(scan);
    Assert.Equal("scan-1", artifacts.ScanId);
    Assert.Equal(1, artifacts.Findings.Count);
    Assert.Equal("CWE-78", artifacts.Findings[0].Cwes.Single());
    var originalFindings = await File.ReadAllTextAsync(Path.Combine(scan, "findings.json"));
    await File.AppendAllTextAsync(Path.Combine(scan, "findings.json"), " ");
    await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadAsync(scan));
    await File.WriteAllTextAsync(Path.Combine(scan, "findings.json"), originalFindings);
    File.Delete(Path.Combine(scan, "coverage.json"));
    await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadAsync(scan));
}

static async Task<string> HashPathAsync(string path)
{
    await using var stream = File.OpenRead(path);
    return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
}

static async Task TestComparisonAsync()
{
    using var fixture = new TemporaryFixture();
    var baseline = fixture.File("baseline.json", BenchmarkReport(precision: 1, recall: 1, passed: true, falsePositives: 0, falseNegatives: 0));
    var candidate = fixture.File("candidate.json", BenchmarkReport(precision: 0.5, recall: 0, passed: false, falsePositives: 1, falseNegatives: 1));
    var comparison = await new BenchmarkComparisonReader().CompareAsync(baseline, candidate);
    Assert.False(comparison.Passed, "Regressed comparison must fail.");
    Assert.True(comparison.Regressions.Any(value => value.Contains("precision", StringComparison.Ordinal)), "Precision regression must be explicit.");
    Assert.True(comparison.Cases.Single().Regressed, "Case regression must be explicit.");
    Assert.True(comparison.CandidateQualityIndex < comparison.BaselineQualityIndex, "Quality index must preserve direction.");

    var differentCorpus = fixture.File(
        "different-corpus.json",
        BenchmarkReport(0.5, 0, false, 1, 1, corpusId: new string('b', 64)));
    await Assert.ThrowsAsync<InvalidDataException>(
        () => new BenchmarkComparisonReader().CompareAsync(baseline, differentCorpus));
    var differentPolicy = fixture.File(
        "different-policy.json",
        BenchmarkReport(0.5, 0, false, 1, 1, comparisonPolicyId: new string('c', 64)));
    await Assert.ThrowsAsync<InvalidDataException>(
        () => new BenchmarkComparisonReader().CompareAsync(baseline, differentPolicy));
    var differentProviderModel = fixture.File(
        "different-provider-model.json",
        BenchmarkReport(1, 1, true, 0, 0,
            scanPolicyId: new string('c', 64),
            scannerLabel: "reference-security",
            model: "reference-model"));
    var crossProvider = await new BenchmarkComparisonReader().CompareAsync(
        baseline,
        differentProviderModel);
    Assert.True(crossProvider.Passed, "Different provider models must remain comparable under the same provider-neutral policy.");
    Assert.True(crossProvider.Markdown.Contains("reference-model", StringComparison.Ordinal), "Comparison output must disclose the differing model.");
    var legacyProvenance = fixture.File(
        "legacy-provenance.json",
        BenchmarkReport(1, 1, true, 0, 0, campaignSchemaVersion: "1.0"));
    await Assert.ThrowsAsync<InvalidDataException>(
        () => new BenchmarkComparisonReader().CompareAsync(baseline, legacyProvenance));
    var legacy = fixture.File(
        "legacy.json",
        BenchmarkReport(0.5, 0, false, 1, 1, includeCampaign: false));
    await Assert.ThrowsAsync<InvalidDataException>(
        () => new BenchmarkComparisonReader().CompareAsync(baseline, legacy));
}

static Task TestSettingsAsync()
{
    using var fixture = new TemporaryFixture();
    var path = Path.Combine(fixture.Root, "state", "gui", "settings.json");
    var store = new GuiSettingsStore();
    store.Save(
        path,
        new GuiSettings
        {
            RepositoryPath = "C:\\work\\repo",
            Model = "gpt-5.6-terra",
            StateRoot = "C:\\state\\.copilot-security",
        });
    var loaded = store.Load(path) ?? throw new InvalidOperationException("Settings were not loaded.");
    Assert.Equal("C:\\work\\repo", loaded.RepositoryPath);
    Assert.False(File.ReadAllText(path).Contains("token", StringComparison.OrdinalIgnoreCase), "Settings contract must contain no credential field.");
    Assert.Equal(0, Directory.EnumerateFiles(Path.GetDirectoryName(path)!, "*.tmp").Count());
    return Task.CompletedTask;
}

static async Task TestProcessRunnerAsync()
{
    var node = FindOnPath("node.exe") ?? FindOnPath("node") ?? throw new InvalidOperationException("Node.js is required for the process test.");
    using var fixture = new TemporaryFixture();
    var progressItems = new List<ScannerProgress>();
    var progress = new InlineProgress<ScannerProgress>(progressItems.Add);
    var runner = new ScannerProcessRunner();
    var completed = await runner.RunAsync(
        new ScannerInvocation(
            node,
            ["-e", "console.error('[12:34] inventory ready'); console.log('ok')"],
            fixture.Root,
            new Dictionary<string, string>()),
        progress,
        CancellationToken.None);
    Assert.True(completed.IsSuccess, completed.FailureMessage ?? "Process should succeed.");
    Assert.True(progressItems.Any(item => item.Stage == "12:34"), "Structured progress line must be parsed.");

    using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
    var stopwatch = Stopwatch.StartNew();
    var canceled = await runner.RunAsync(
        new ScannerInvocation(
            node,
            ["-e", "setInterval(() => {}, 1000)"],
            fixture.Root,
            new Dictionary<string, string>()),
        null,
        cancellation.Token);
    Assert.Equal(ScanRunState.Canceled, canceled.State);
    Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "Cancellation must terminate promptly.");
}

static string BenchmarkReport(
    double precision,
    double recall,
    bool passed,
    int falsePositives,
    int falseNegatives,
    string? corpusId = null,
    string? scanPolicyId = null,
    string? comparisonPolicyId = null,
    string campaignSchemaVersion = "1.1",
    string scannerLabel = "copilot-security",
    string model = "gpt-5.6-terra",
    bool includeCampaign = true)
{
    var f1 = precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall);
    var payload = new Dictionary<string, object?>
    {
        ["documentType"] = "copilot-security.benchmark",
        ["schemaVersion"] = "1.0",
        ["generatedAt"] = "2026-07-31T00:00:00Z",
        ["manifestPath"] = "manifest.json",
        ["resultsDirectory"] = "results",
        ["passed"] = passed,
        ["metrics"] = new
        {
            caseCount = 1,
            runCount = 1,
            completedRuns = 1,
            completionRate = 1,
            expectedInstances = 1,
            reportedFindings = 1 + falsePositives - falseNegatives,
            truePositives = 1 - falseNegatives,
            falsePositives,
            falseNegatives,
            precision,
            recall,
            f1,
            casePassRate = passed ? 1 : 0,
            negativeCasePassRate = 1,
            stableDetectionRate = passed ? 1 : 0,
            validationRate = passed ? 1 : 0,
            attackPathRate = passed ? 1 : 0,
            codeEvidenceRate = passed ? 1 : 0,
            severityAccuracy = passed ? 1 : 0,
            falsePositivesPerRun = falsePositives,
        },
        ["thresholds"] = Array.Empty<object>(),
        ["cases"] = new[]
        {
            new
            {
                id = "case-1",
                expectedCount = 1,
                stableExpectations = passed ? new[] { "expectation" } : Array.Empty<string>(),
                unstableExpectations = Array.Empty<string>(),
                passed,
                runs = new[]
                {
                    new
                    {
                        id = "run-1",
                        findingsPath = "findings.json",
                        completed = true,
                        expectedCount = 1,
                        findingCount = 1 + falsePositives - falseNegatives,
                        truePositives = 1 - falseNegatives,
                        falsePositives,
                        falseNegatives,
                        passed,
                        matches = Array.Empty<object>(),
                        missedExpectations = Array.Empty<string>(),
                        unexpectedFindings = Array.Empty<string>(),
                    },
                },
            },
        },
    };
    if (includeCampaign)
    {
        payload["campaign"] = new
        {
            documentType = "copilot-security.benchmark-campaign",
            schemaVersion = campaignSchemaVersion,
            campaignId = new string('d', 64),
            corpusId = corpusId ?? new string('a', 64),
            scanPolicyId = scanPolicyId ?? new string('b', 64),
            comparisonPolicyId = campaignSchemaVersion == "1.1"
                ? comparisonPolicyId ?? new string('e', 64)
                : null,
            scanner = new
            {
                label = scannerLabel,
            },
            scan = new
            {
                model,
                auth = "github",
            },
        };
    }
    return JsonSerializer.Serialize(payload);
}

static string? FindOnPath(string executable)
{
    foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
        .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        var path = Path.Combine(directory.Trim('"'), executable);
        if (File.Exists(path))
        {
            return path;
        }
    }
    return null;
}

sealed class TemporaryFixture : IDisposable
{
    public TemporaryFixture()
    {
        Root = Path.Combine(Path.GetTempPath(), "copilot-security-gui-tests-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string Directory(string relative)
    {
        var path = Path.Combine(Root, relative);
        System.IO.Directory.CreateDirectory(path);
        return path;
    }

    public string File(string relative, string content = "")
    {
        var path = Path.Combine(Root, relative);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllText(path, content);
        return path;
    }

    public ScannerInstallation Installation() => new(
        File("runtime/node.exe"),
        File("scanner/copilot-security.mjs"),
        File("runtime/copilot.cmd"),
        Path.Combine(Root, ".copilot-security"));

    public void Dispose()
    {
        try
        {
            System.IO.Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
            // Windows antivirus and process teardown can briefly retain a test file.
        }
    }
}

sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}

static class Assert
{
    public static void True(bool value, string message = "Expected true.")
    {
        if (!value) throw new InvalidOperationException(message);
    }

    public static void False(bool value, string message = "Expected false.") => True(!value, message);

    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}; received {actual}.");
        }
    }

    public static void Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException("Expected exception " + typeof(T).Name + ".");
    }

    public static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try
        {
            await action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException("Expected exception " + typeof(T).Name + ".");
    }
}
