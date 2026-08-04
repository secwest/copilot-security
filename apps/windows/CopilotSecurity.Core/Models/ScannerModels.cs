using System.Collections.ObjectModel;

namespace Secwest.CopilotSecurity.Core.Models;

public enum ScanMode
{
    Standard,
    Deep,
}

public enum ScanTargetKind
{
    Repository,
    CommittedDiff,
    WorkingTree,
}

public enum ScanRunState
{
    NotStarted,
    Running,
    Completed,
    Failed,
    Canceled,
}

public sealed record ScannerInstallation(
    string NodeExecutable,
    string ScannerEntryPoint,
    string CopilotExecutable,
    string StateRoot)
{
    public string RuntimeHome => Path.Combine(StateRoot, "copilot-security-home");
}

public sealed record ScanRequest
{
    public required string RepositoryPath { get; init; }
    public required string OutputDirectory { get; init; }
    public ScanMode Mode { get; init; } = ScanMode.Deep;
    public ScanTargetKind TargetKind { get; init; } = ScanTargetKind.Repository;
    public string AuthMode { get; init; } = "github";
    public string Model { get; init; } = "auto";
    public string Effort { get; init; } = "high";
    public string? BaseRevision { get; init; }
    public string HeadRevision { get; init; } = "HEAD";
    public string? FailOnSeverity { get; init; }
    public decimal? MaximumCostUsd { get; init; }
    public int? MaximumAiCredits { get; init; }
    public TimeSpan ModelTurnTimeout { get; init; } = TimeSpan.FromHours(1);
    public IReadOnlyList<string> IncludePaths { get; init; } = [];
    public IReadOnlyList<string> KnowledgeBasePaths { get; init; } = [];
    public IReadOnlyList<string> SarifSeedPaths { get; init; } = [];
    public string? SarifSourceRoot { get; init; }
    public string? SecretBaselinePath { get; init; }
}

public sealed record ScannerInvocation(
    string FileName,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    IReadOnlyDictionary<string, string> Environment);

public sealed record ScannerProgress(
    DateTimeOffset Timestamp,
    string Stage,
    string Message,
    string RawLine);

public sealed record ScannerProcessResult(
    ScanRunState State,
    int? ExitCode,
    TimeSpan Elapsed,
    string StandardOutput,
    string StandardError,
    string? FailureMessage)
{
    public bool IsSuccess => State == ScanRunState.Completed && ExitCode == 0;
}

public sealed record FindingLocation(
    string Path,
    int StartLine,
    int? EndLine,
    string Role);

public sealed record ScanFinding(
    string FindingId,
    string Title,
    string Summary,
    string Severity,
    string Confidence,
    string Category,
    IReadOnlyList<string> Cwes,
    IReadOnlyList<FindingLocation> Locations,
    string Validation,
    string AttackPath,
    string Remediation);

public sealed record ScanArtifacts(
    string ScanDirectory,
    string ReportPath,
    string ManifestPath,
    string FindingsPath,
    string CoveragePath,
    string ScanId,
    string Status,
    string CoverageCompleteness,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    IReadOnlyList<ScanFinding> Findings,
    string ReportMarkdown);

public sealed record ScanHistoryItem(
    string ScanDirectory,
    string ScanId,
    string Repository,
    string Status,
    string Coverage,
    int FindingCount,
    DateTimeOffset? CompletedAt);

public sealed class ScanSession
{
    public ScanRunState State { get; internal set; } = ScanRunState.NotStarted;
    public ObservableCollection<ScannerProgress> Progress { get; } = [];
    public ScannerProcessResult? ProcessResult { get; internal set; }
    public ScanArtifacts? Artifacts { get; internal set; }
}
