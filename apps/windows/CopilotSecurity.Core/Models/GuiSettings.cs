namespace Secwest.CopilotSecurity.Core.Models;

public sealed record GuiSettings
{
    public string RepositoryPath { get; init; } = string.Empty;
    public string NodePath { get; init; } = string.Empty;
    public string ScannerEntryPoint { get; init; } = string.Empty;
    public string CopilotPath { get; init; } = string.Empty;
    public string StateRoot { get; init; } = string.Empty;
    public string Model { get; init; } = "auto";
    public string Effort { get; init; } = "high";
    public string AuthMode { get; init; } = "github";
    public ScanMode Mode { get; init; } = ScanMode.Deep;
    public ScanTargetKind TargetKind { get; init; } = ScanTargetKind.Repository;
    public string BaseRevision { get; init; } = "origin/main";
    public string HeadRevision { get; init; } = "HEAD";
    public int SecretHistoryDepth { get; init; } = 128;
    public string BenchmarkManifest { get; init; } = string.Empty;
    public string BenchmarkResultsDirectory { get; init; } = string.Empty;
}
