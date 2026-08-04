using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using Secwest.CopilotSecurity.Core.Models;
using Secwest.CopilotSecurity.Core.Services;
using Secwest.CopilotSecurity.Desktop.Infrastructure;

namespace Secwest.CopilotSecurity.Desktop.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly ScannerCommandBuilder commandBuilder = new();
    private readonly ScannerProcessRunner processRunner = new();
    private readonly ScanArtifactReader artifactReader = new();
    private readonly BenchmarkComparisonReader benchmarkComparisonReader = new();
    private readonly GuiSettingsStore settingsStore = new();
    private readonly DesktopPlatformOptions platform;
    private readonly string settingsPath;
    private CancellationTokenSource? operationCancellation;
    private string repositoryPath = Environment.CurrentDirectory;
    private string nodePath = string.Empty;
    private string copilotPath = string.Empty;
    private string scannerEntryPoint = DiscoverScannerEntryPoint();
    private string stateRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".copilot-security");
    private string model = "auto";
    private string effort = "high";
    private string authMode = "github";
    private ScanMode mode = ScanMode.Deep;
    private ScanTargetKind targetKind;
    private string baseRevision = "origin/main";
    private string headRevision = "HEAD";
    private string includePaths = string.Empty;
    private string knowledgeBasePaths = string.Empty;
    private string sarifSeedPaths = string.Empty;
    private string sarifSourceRoot = string.Empty;
    private string secretBaselinePath = string.Empty;
    private string maximumCost = string.Empty;
    private string maximumCredits = string.Empty;
    private string status = "Ready";
    private string currentStage = "idle";
    private string reportMarkdown = "Run or select a scan to view its report.";
    private ScanFinding? selectedFinding;
    private ScanHistoryItem? selectedHistory;
    private string benchmarkManifest = ScannerInstallationDiscovery.FindInstalledFile(
        AppContext.BaseDirectory,
        "benchmarks",
        "manifest.json") ?? string.Empty;
    private string benchmarkResultsDirectory = string.Empty;
    private string baselineBenchmarkReport = string.Empty;
    private string candidateBenchmarkReport = string.Empty;
    private bool benchmarkRequireStatus = true;
    private string benchmarkOutput = "Benchmark execution output will appear here.";
    private bool isBusy;
    private TimeSpan elapsed;

    public MainViewModel(DesktopPlatformOptions? platformOptions = null)
    {
        platform = platformOptions ?? DesktopPlatformOptions.Current();
        settingsPath = platform.SettingsPath;
        nodePath = FindOnPath(platform.NodeExecutableNames) ?? string.Empty;
        copilotPath = FindOnPath(platform.CopilotExecutableNames) ?? string.Empty;
        LoadSettings();
        StartScanCommand = new AsyncRelayCommand(StartScanAsync, () => !IsBusy);
        CancelCommand = new RelayCommand(Cancel, () => IsBusy);
        RefreshHistoryCommand = new AsyncRelayCommand(RefreshHistoryAsync, () => !IsBusy);
        LoadHistoryCommand = new AsyncRelayCommand(LoadSelectedHistoryAsync, () => SelectedHistory is not null);
        OpenReportCommand = new RelayCommand(OpenReport, () => CurrentArtifacts is not null);
        RunBenchmarkCommand = new AsyncRelayCommand(RunBenchmarkAsync, () => !IsBusy);
        CompareBenchmarksCommand = new AsyncRelayCommand(CompareBenchmarksAsync, () => !IsBusy);
        RefreshDiagnosticsCommand = new AsyncRelayCommand(RefreshDiagnosticsAsync, () => !IsBusy);
        if (string.IsNullOrWhiteSpace(benchmarkResultsDirectory))
        {
            benchmarkResultsDirectory = Path.Combine(RuntimeHome, platform.BenchmarkDirectoryName);
        }
        candidateBenchmarkReport = Path.Combine(benchmarkResultsDirectory, "benchmark-report.json");
        _ = RefreshHistoryAsync();
        _ = RefreshDiagnosticsAsync();
    }

    public ObservableCollection<ScannerProgress> ProgressItems { get; } = [];
    public ObservableCollection<ScanFinding> Findings { get; } = [];
    public ObservableCollection<ScanHistoryItem> History { get; } = [];
    public ObservableCollection<string> DiagnosticItems { get; } = [];
    public IReadOnlyList<ScanMode> Modes { get; } = Enum.GetValues<ScanMode>();
    public IReadOnlyList<ScanTargetKind> TargetKinds { get; } = Enum.GetValues<ScanTargetKind>();
    public IReadOnlyList<string> Efforts { get; } = ["low", "medium", "high", "xhigh"];
    public IReadOnlyList<string> AuthModes { get; } = ["auto", "github", "token"];
    public IReadOnlyList<string> ModelSuggestions { get; } =
        ["auto", "gpt-5.4", "claude-opus-4.6", "claude-sonnet-4.6", "gpt-5.6-terra", "gpt-5.6-sol"];

    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelCommand { get; }
    public AsyncRelayCommand RefreshHistoryCommand { get; }
    public AsyncRelayCommand LoadHistoryCommand { get; }
    public RelayCommand OpenReportCommand { get; }
    public AsyncRelayCommand RunBenchmarkCommand { get; }
    public AsyncRelayCommand CompareBenchmarksCommand { get; }
    public AsyncRelayCommand RefreshDiagnosticsCommand { get; }

    public string RepositoryPath { get => repositoryPath; set => SetProperty(ref repositoryPath, value); }
    public string NodePath { get => nodePath; set => SetProperty(ref nodePath, value); }
    public string CopilotPath { get => copilotPath; set => SetProperty(ref copilotPath, value); }
    public string ScannerEntryPoint { get => scannerEntryPoint; set => SetProperty(ref scannerEntryPoint, value); }
    public string StateRoot
    {
        get => stateRoot;
        set
        {
            if (SetProperty(ref stateRoot, value))
            {
                RaisePropertyChanged(nameof(RuntimeHome));
                RaisePropertyChanged(nameof(HistoryRoot));
                BenchmarkResultsDirectory = Path.Combine(RuntimeHome, platform.BenchmarkDirectoryName);
            }
        }
    }
    public string RuntimeHome => Path.Combine(StateRoot, "copilot-security-home");
    public string HistoryRoot => Path.Combine(RuntimeHome, platform.HistoryDirectoryName);
    public string Model { get => model; set => SetProperty(ref model, value); }
    public string Effort { get => effort; set => SetProperty(ref effort, value); }
    public string AuthMode { get => authMode; set => SetProperty(ref authMode, value); }
    public ScanMode Mode { get => mode; set => SetProperty(ref mode, value); }
    public ScanTargetKind TargetKind { get => targetKind; set => SetProperty(ref targetKind, value); }
    public string BaseRevision { get => baseRevision; set => SetProperty(ref baseRevision, value); }
    public string HeadRevision { get => headRevision; set => SetProperty(ref headRevision, value); }
    public string IncludePaths { get => includePaths; set => SetProperty(ref includePaths, value); }
    public string KnowledgeBasePaths { get => knowledgeBasePaths; set => SetProperty(ref knowledgeBasePaths, value); }
    public string SarifSeedPaths { get => sarifSeedPaths; set => SetProperty(ref sarifSeedPaths, value); }
    public string SarifSourceRoot { get => sarifSourceRoot; set => SetProperty(ref sarifSourceRoot, value); }
    public string SecretBaselinePath { get => secretBaselinePath; set => SetProperty(ref secretBaselinePath, value); }
    public string MaximumCost { get => maximumCost; set => SetProperty(ref maximumCost, value); }
    public string MaximumCredits { get => maximumCredits; set => SetProperty(ref maximumCredits, value); }
    public string Status { get => status; private set => SetProperty(ref status, value); }
    public string CurrentStage { get => currentStage; private set => SetProperty(ref currentStage, value); }
    public string ReportMarkdown { get => reportMarkdown; private set => SetProperty(ref reportMarkdown, value); }
    public ScanFinding? SelectedFinding { get => selectedFinding; set => SetProperty(ref selectedFinding, value); }
    public ScanHistoryItem? SelectedHistory
    {
        get => selectedHistory;
        set
        {
            if (SetProperty(ref selectedHistory, value))
            {
                LoadHistoryCommand.RaiseCanExecuteChanged();
            }
        }
    }
    public string BenchmarkManifest { get => benchmarkManifest; set => SetProperty(ref benchmarkManifest, value); }
    public string BenchmarkResultsDirectory
    {
        get => benchmarkResultsDirectory;
        set
        {
            if (SetProperty(ref benchmarkResultsDirectory, value))
            {
                CandidateBenchmarkReport = Path.Combine(value, "benchmark-report.json");
            }
        }
    }
    public string BaselineBenchmarkReport { get => baselineBenchmarkReport; set => SetProperty(ref baselineBenchmarkReport, value); }
    public string CandidateBenchmarkReport { get => candidateBenchmarkReport; set => SetProperty(ref candidateBenchmarkReport, value); }
    public bool BenchmarkRequireStatus { get => benchmarkRequireStatus; set => SetProperty(ref benchmarkRequireStatus, value); }
    public string BenchmarkOutput { get => benchmarkOutput; private set => SetProperty(ref benchmarkOutput, value); }
    public bool IsBusy
    {
        get => isBusy;
        private set
        {
            if (SetProperty(ref isBusy, value))
            {
                StartScanCommand.RaiseCanExecuteChanged();
                CancelCommand.RaiseCanExecuteChanged();
                RefreshHistoryCommand.RaiseCanExecuteChanged();
                RunBenchmarkCommand.RaiseCanExecuteChanged();
                CompareBenchmarksCommand.RaiseCanExecuteChanged();
                RefreshDiagnosticsCommand.RaiseCanExecuteChanged();
            }
        }
    }
    public TimeSpan Elapsed { get => elapsed; private set => SetProperty(ref elapsed, value); }
    public ScanArtifacts? CurrentArtifacts { get; private set; }

    private ScannerInstallation Installation => new(NodePath, ScannerEntryPoint, CopilotPath, StateRoot);

    private static string DiscoverScannerEntryPoint() =>
        ScannerInstallationDiscovery.FindInstalledFile(
            AppContext.BaseDirectory,
            "scanner",
            "bin",
            "copilot-security.mjs")
        ?? ScannerInstallationDiscovery.FindInstalledFile(
            AppContext.BaseDirectory,
            "sdk",
            "typescript",
            "bin",
            "copilot-security.mjs")
        ?? string.Empty;

    private async Task StartScanAsync()
    {
        IsBusy = true;
        ProgressItems.Clear();
        Findings.Clear();
        SelectedFinding = null;
        CurrentArtifacts = null;
        OpenReportCommand.RaiseCanExecuteChanged();
        var runDirectory = NewRunDirectory();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(runDirectory)!);
            var request = new ScanRequest
            {
                RepositoryPath = RepositoryPath,
                OutputDirectory = runDirectory,
                Mode = Mode,
                TargetKind = TargetKind,
                AuthMode = AuthMode,
                Model = Model,
                Effort = Effort,
                BaseRevision = BaseRevision,
                HeadRevision = HeadRevision,
                IncludePaths = ParsePaths(IncludePaths, RepositoryPath),
                KnowledgeBasePaths = ParsePaths(KnowledgeBasePaths, RepositoryPath),
                SarifSeedPaths = ParsePaths(SarifSeedPaths, RepositoryPath),
                SarifSourceRoot = string.IsNullOrWhiteSpace(SarifSourceRoot)
                    ? null
                    : Path.IsPathRooted(SarifSourceRoot)
                        ? SarifSourceRoot
                        : Path.Combine(RepositoryPath, SarifSourceRoot),
                SecretBaselinePath = string.IsNullOrWhiteSpace(SecretBaselinePath)
                    ? null
                    : Path.IsPathRooted(SecretBaselinePath)
                        ? SecretBaselinePath
                        : Path.Combine(RepositoryPath, SecretBaselinePath),
                MaximumCostUsd = ParseOptionalDecimal(MaximumCost, "Maximum cost"),
                MaximumAiCredits = ParseOptionalInt(MaximumCredits, "Maximum credits"),
            };
            var invocation = commandBuilder.BuildScan(Installation, request);
            operationCancellation = new CancellationTokenSource();
            Status = "Scanner running";
            CurrentStage = "starting";
            var progress = new Progress<ScannerProgress>(item =>
            {
                CurrentStage = item.Stage;
                AddProgress(item);
            });
            var result = await processRunner.RunAsync(
                invocation,
                progress,
                operationCancellation.Token).ConfigureAwait(true);
            Elapsed = result.Elapsed;
            if (!result.IsSuccess)
            {
                Status = result.State == ScanRunState.Canceled ? "Canceled" : "Scan failed";
                CurrentStage = result.State.ToString().ToLowerInvariant();
                ReportMarkdown = BuildFailureReport(result, runDirectory);
                return;
            }

            CurrentArtifacts = await artifactReader.ReadAsync(runDirectory).ConfigureAwait(true);
            foreach (var finding in CurrentArtifacts.Findings)
            {
                Findings.Add(finding);
            }
            SelectedFinding = Findings.FirstOrDefault();
            ReportMarkdown = CurrentArtifacts.ReportMarkdown;
            Status = $"Completed: {Findings.Count} finding(s), coverage {CurrentArtifacts.CoverageCompleteness}";
            CurrentStage = "complete";
            OpenReportCommand.RaiseCanExecuteChanged();
            await RefreshHistoryAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            Status = "Scan could not start or its artifacts were invalid";
            CurrentStage = "error";
            ReportMarkdown = "# Scan error\n\n" + exception.Message + "\n\nNo result was accepted as complete.";
        }
        finally
        {
            operationCancellation?.Dispose();
            operationCancellation = null;
            IsBusy = false;
        }
    }

    private async Task RunBenchmarkAsync()
    {
        IsBusy = true;
        try
        {
            Directory.CreateDirectory(BenchmarkResultsDirectory);
            var invocation = commandBuilder.BuildBenchmark(
                Installation,
                BenchmarkManifest,
                BenchmarkResultsDirectory,
                BenchmarkRequireStatus);
            operationCancellation = new CancellationTokenSource();
            Status = "Benchmark running";
            var progress = new Progress<ScannerProgress>(item =>
            {
                CurrentStage = item.Stage;
                AddProgress(item);
            });
            var result = await processRunner.RunAsync(invocation, progress, operationCancellation.Token)
                .ConfigureAwait(true);
            Elapsed = result.Elapsed;
            BenchmarkOutput = result.StandardOutput.Length > 0
                ? result.StandardOutput
                : result.StandardError;
            if (!result.IsSuccess && result.FailureMessage is not null)
            {
                BenchmarkOutput += Environment.NewLine + result.FailureMessage;
            }
            Status = result.IsSuccess ? "Benchmark completed" : result.State.ToString();
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            Status = "Benchmark failed safely";
            BenchmarkOutput = exception.Message;
        }
        finally
        {
            operationCancellation?.Dispose();
            operationCancellation = null;
            IsBusy = false;
        }
    }

    private async Task CompareBenchmarksAsync()
    {
        IsBusy = true;
        try
        {
            var comparison = await benchmarkComparisonReader.CompareAsync(
                BaselineBenchmarkReport,
                CandidateBenchmarkReport).ConfigureAwait(true);
            BenchmarkOutput = comparison.Markdown;
            Status = comparison.Passed
                ? $"Comparison passed; quality {comparison.BaselineQualityIndex:0.0000} → {comparison.CandidateQualityIndex:0.0000}"
                : $"Comparison found {comparison.Regressions.Count} regression(s)";
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            Status = "Benchmark comparison rejected";
            BenchmarkOutput = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshHistoryAsync()
    {
        try
        {
            var items = await artifactReader.ReadHistoryAsync(HistoryRoot).ConfigureAwait(true);
            History.Clear();
            foreach (var item in items)
            {
                History.Add(item);
            }
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            Status = "History unavailable: " + exception.Message;
        }
    }

    private async Task LoadSelectedHistoryAsync()
    {
        if (SelectedHistory is null)
        {
            return;
        }

        try
        {
            var artifacts = await artifactReader.ReadAsync(SelectedHistory.ScanDirectory).ConfigureAwait(true);
            CurrentArtifacts = artifacts;
            Findings.Clear();
            foreach (var finding in artifacts.Findings)
            {
                Findings.Add(finding);
            }
            SelectedFinding = Findings.FirstOrDefault();
            ReportMarkdown = artifacts.ReportMarkdown;
            Status = $"Loaded {artifacts.ScanId}";
            OpenReportCommand.RaiseCanExecuteChanged();
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            Status = "Stored scan is incomplete or invalid: " + exception.Message;
        }
    }

    private Task RefreshDiagnosticsAsync()
    {
        DiagnosticItems.Clear();
        AddPathDiagnostic("Node.js", NodePath);
        AddPathDiagnostic("Copilot CLI", CopilotPath);
        AddPathDiagnostic("Scanner entry point", ScannerEntryPoint);
        DiagnosticItems.Add("State root: " + StateRoot);
        DiagnosticItems.Add("Private runtime home: " + RuntimeHome);
        DiagnosticItems.Add("Operating system: " + Environment.OSVersion);
        DiagnosticItems.Add("Runtime: " + Environment.Version);
        DiagnosticItems.Add("Process architecture: " + System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture);
        return Task.CompletedTask;
    }

    private void AddPathDiagnostic(string label, string path) =>
        DiagnosticItems.Add($"{label}: {(File.Exists(path) ? "ready" : "missing")} — {path}");

    private void AddProgress(ScannerProgress item)
    {
        ProgressItems.Add(item);
        if (ProgressItems.Count > 5_000)
        {
            ProgressItems.RemoveAt(0);
        }
    }

    private void Cancel() => operationCancellation?.Cancel();

    private void OpenReport()
    {
        var artifacts = CurrentArtifacts;
        if (artifacts is null || !File.Exists(artifacts.ReportPath))
        {
            return;
        }
        Process.Start(new ProcessStartInfo(artifacts.ReportPath) { UseShellExecute = true });
    }

    private string NewRunDirectory()
    {
        var name = Path.GetFileName(Path.GetFullPath(RepositoryPath).TrimEnd(Path.DirectorySeparatorChar));
        var safeName = new string(name.Select(character =>
            Path.GetInvalidFileNameChars().Contains(character) ? '_' : character).ToArray());
        return Path.Combine(
            HistoryRoot,
            DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture) + "-" + safeName);
    }

    private IReadOnlyList<string> ParsePaths(string value, string repository) =>
        value.Split([';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(path => Path.IsPathRooted(path) ? path : Path.Combine(repository, path))
            .Distinct(platform.PathComparer)
            .ToArray();

    private static decimal? ParseOptionalDecimal(string value, string label)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        return decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var result)
            ? result
            : throw new ArgumentException(label + " must be a decimal number using a period as the separator.");
    }

    private static int? ParseOptionalInt(string value, string label)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var result)
            ? result
            : throw new ArgumentException(label + " must be a whole number.");
    }

    private static string BuildFailureReport(ScannerProcessResult result, string outputDirectory)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Scan did not complete");
        builder.AppendLine();
        builder.AppendLine(result.FailureMessage ?? result.State.ToString());
        builder.AppendLine();
        builder.AppendLine("Partial artifacts, if written, remain at:");
        builder.AppendLine(outputDirectory);
        builder.AppendLine();
        builder.AppendLine("The GUI did not accept partial artifacts as a completed result.");
        return builder.ToString();
    }

    private static bool IsRecoverable(Exception exception) =>
        exception is ArgumentException or IOException or InvalidDataException or UnauthorizedAccessException;

    private static string? FindOnPath(IEnumerable<string> executableNames)
    {
        foreach (var executable in executableNames)
        {
            if (Path.IsPathRooted(executable) && IsRunnable(executable))
            {
                return Path.GetFullPath(executable);
            }
            foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                try
                {
                    var candidate = Path.Combine(directory.Trim('"'), executable);
                    if (IsRunnable(candidate))
                    {
                        return Path.GetFullPath(candidate);
                    }
                }
                catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
                {
                    // Ignore malformed PATH entries and continue through the bounded list.
                }
            }
        }
        return null;
    }

    private static bool IsRunnable(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }
        if (OperatingSystem.IsWindows())
        {
            return true;
        }
        try
        {
            const UnixFileMode executable = UnixFileMode.UserExecute
                | UnixFileMode.GroupExecute
                | UnixFileMode.OtherExecute;
            return (File.GetUnixFileMode(path) & executable) != 0;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private void LoadSettings()
    {
        try
        {
            var settings = settingsStore.Load(settingsPath);
            if (settings is null)
            {
                return;
            }
            repositoryPath = Prefer(settings.RepositoryPath, repositoryPath);
            nodePath = Prefer(settings.NodePath, nodePath);
            scannerEntryPoint = Prefer(settings.ScannerEntryPoint, scannerEntryPoint);
            copilotPath = Prefer(settings.CopilotPath, copilotPath);
            stateRoot = Prefer(settings.StateRoot, stateRoot);
            model = Prefer(settings.Model, model);
            effort = Prefer(settings.Effort, effort);
            authMode = Prefer(settings.AuthMode, authMode);
            mode = settings.Mode;
            targetKind = settings.TargetKind;
            baseRevision = Prefer(settings.BaseRevision, baseRevision);
            headRevision = Prefer(settings.HeadRevision, headRevision);
            benchmarkManifest = Prefer(settings.BenchmarkManifest, benchmarkManifest);
            benchmarkResultsDirectory = Prefer(
                settings.BenchmarkResultsDirectory,
                Path.Combine(stateRoot, "copilot-security-home", platform.BenchmarkDirectoryName));
        }
        catch (Exception exception) when (IsRecoverable(exception) || exception is JsonException)
        {
            status = "Settings were invalid and defaults were restored: " + exception.Message;
        }
    }

    private static string Prefer(string candidate, string fallback) =>
        string.IsNullOrWhiteSpace(candidate) ? fallback : candidate;

    public void Dispose()
    {
        operationCancellation?.Cancel();
        operationCancellation?.Dispose();
        operationCancellation = null;
        try
        {
            settingsStore.Save(
                settingsPath,
                new GuiSettings
                {
                    RepositoryPath = RepositoryPath,
                    NodePath = NodePath,
                    ScannerEntryPoint = ScannerEntryPoint,
                    CopilotPath = CopilotPath,
                    StateRoot = StateRoot,
                    Model = Model,
                    Effort = Effort,
                    AuthMode = AuthMode,
                    Mode = Mode,
                    TargetKind = TargetKind,
                    BaseRevision = BaseRevision,
                    HeadRevision = HeadRevision,
                    BenchmarkManifest = BenchmarkManifest,
                    BenchmarkResultsDirectory = BenchmarkResultsDirectory,
                });
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            Debug.WriteLine("Settings were not persisted: " + exception.Message);
        }
        GC.SuppressFinalize(this);
    }
}
