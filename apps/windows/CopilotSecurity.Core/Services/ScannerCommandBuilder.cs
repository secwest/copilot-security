using System.Globalization;
using Secwest.CopilotSecurity.Core.Models;

namespace Secwest.CopilotSecurity.Core.Services;

public sealed class ScannerCommandBuilder
{
    private static readonly HashSet<string> AuthModes = new(StringComparer.Ordinal)
    {
        "auto",
        "github",
        "token",
    };

    private static readonly HashSet<string> Efforts = new(StringComparer.Ordinal)
    {
        "low",
        "medium",
        "high",
        "xhigh",
    };

    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal)
    {
        "critical",
        "high",
        "medium",
        "low",
    };

    public ScannerInvocation BuildScan(ScannerInstallation installation, ScanRequest request)
    {
        ArgumentNullException.ThrowIfNull(installation);
        ArgumentNullException.ThrowIfNull(request);

        var node = PathPolicy.ExistingFile(installation.NodeExecutable, "Node executable");
        var entryPoint = PathPolicy.ExistingFile(
            installation.ScannerEntryPoint,
            "Scanner entry point");
        var copilot = PathPolicy.ExistingFile(installation.CopilotExecutable, "Copilot executable");
        PathPolicy.RequireScannerOwnedState(installation.StateRoot);

        var repository = PathPolicy.ExistingDirectory(request.RepositoryPath, "Repository");
        var output = PathPolicy.Canonical(request.OutputDirectory, "Output directory");
        var stateRoot = PathPolicy.Canonical(installation.StateRoot, "Scanner state root");
        var runtimeHome = Path.Combine(stateRoot, "copilot-security-home");
        PathPolicy.RequireNoReparseAncestors(output, "Output directory");

        PathPolicy.RequireDisjoint(
            output,
            repository,
            "Output directory and scanned repository must be disjoint.");
        PathPolicy.RequireDisjoint(
            runtimeHome,
            repository,
            "COPILOT_SECURITY_HOME/copilot-security-home and the scanned repository must be disjoint.");

        if (!AuthModes.Contains(request.AuthMode))
        {
            throw new ArgumentException("Unsupported authentication mode.", nameof(request));
        }
        if (!Efforts.Contains(request.Effort))
        {
            throw new ArgumentException("Unsupported model effort.", nameof(request));
        }
        if (string.IsNullOrWhiteSpace(request.Model) || request.Model.Length > 128)
        {
            throw new ArgumentException("Model must be a non-empty bounded identifier.", nameof(request));
        }
        if (request.FailOnSeverity is not null && !Severities.Contains(request.FailOnSeverity))
        {
            throw new ArgumentException("Unsupported failure severity.", nameof(request));
        }
        if (request.MaximumCostUsd is <= 0)
        {
            throw new ArgumentException("Maximum cost must be positive when supplied.", nameof(request));
        }
        if (request.MaximumAiCredits is < 30)
        {
            throw new ArgumentException("Maximum AI credits must be at least 30 when supplied.", nameof(request));
        }
        if (request.ModelTurnTimeout < TimeSpan.FromMinutes(1) ||
            request.ModelTurnTimeout > TimeSpan.FromHours(24))
        {
            throw new ArgumentException("Model turn timeout must be from one minute through 24 hours.", nameof(request));
        }

        ValidateTarget(request);
        var arguments = new List<string>
        {
            entryPoint,
            "scan",
            repository,
            "--auth",
            request.AuthMode,
            "--model",
            request.Model.Trim(),
            "--effort",
            request.Effort,
            "--mode",
            request.Mode == ScanMode.Deep ? "deep" : "standard",
            "--output-dir",
            output,
            "--format",
            "json",
            "--full-output",
        };

        AppendTarget(arguments, request);
        AppendRepeatedPath(arguments, "--path", repository, request.IncludePaths);
        AppendRepeatedPath(
            arguments,
            "--knowledge-base",
            repository,
            request.KnowledgeBasePaths,
            requireInsideRepository: false);

        if (request.FailOnSeverity is not null)
        {
            arguments.Add("--fail-on-severity");
            arguments.Add(request.FailOnSeverity);
        }
        if (request.MaximumCostUsd is not null)
        {
            arguments.Add("--max-cost");
            arguments.Add(request.MaximumCostUsd.Value.ToString(CultureInfo.InvariantCulture));
        }
        if (request.MaximumAiCredits is not null)
        {
            arguments.Add("--max-ai-credits");
            arguments.Add(request.MaximumAiCredits.Value.ToString(CultureInfo.InvariantCulture));
        }

        return new ScannerInvocation(
            node,
            arguments,
            repository,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["COPILOT_SECURITY_HOME"] = stateRoot,
                ["COPILOT_CLI_PATH"] = copilot,
                ["COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS"] =
                    ((long)request.ModelTurnTimeout.TotalMilliseconds).ToString(
                        CultureInfo.InvariantCulture),
            });
    }

    public ScannerInvocation BuildBenchmark(
        ScannerInstallation installation,
        string manifestPath,
        string resultsDirectory,
        bool requireStatus)
    {
        var node = PathPolicy.ExistingFile(installation.NodeExecutable, "Node executable");
        var entryPoint = PathPolicy.ExistingFile(
            installation.ScannerEntryPoint,
            "Scanner entry point");
        var copilot = PathPolicy.ExistingFile(installation.CopilotExecutable, "Copilot executable");
        var manifest = PathPolicy.ExistingFile(manifestPath, "Benchmark manifest");
        var results = PathPolicy.Canonical(resultsDirectory, "Benchmark results directory");
        PathPolicy.RequireScannerOwnedState(installation.StateRoot);
        PathPolicy.RequireNoReparseAncestors(results, "Benchmark results directory");

        var arguments = new List<string>
        {
            entryPoint,
            "benchmark",
            manifest,
            "--results-dir",
            results,
            "--format",
            "json",
            "--full-output",
        };
        if (requireStatus)
        {
            arguments.Add("--require-status");
        }

        return new ScannerInvocation(
            node,
            arguments,
            Path.GetDirectoryName(manifest)!,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["COPILOT_SECURITY_HOME"] = Path.GetFullPath(installation.StateRoot),
                ["COPILOT_CLI_PATH"] = copilot,
            });
    }

    private static void ValidateTarget(ScanRequest request)
    {
        if (request.TargetKind != ScanTargetKind.Repository && request.Mode == ScanMode.Deep)
        {
            throw new ArgumentException("Deep mode supports repository and scoped-path scans, not diff scans.");
        }
        if (request.TargetKind == ScanTargetKind.CommittedDiff &&
            string.IsNullOrWhiteSpace(request.BaseRevision))
        {
            throw new ArgumentException("Committed diff scans require a base revision.");
        }
        if (request.TargetKind == ScanTargetKind.WorkingTree &&
            string.IsNullOrWhiteSpace(request.BaseRevision))
        {
            throw new ArgumentException("Working-tree scans require a base revision.");
        }
    }

    private static void AppendTarget(List<string> arguments, ScanRequest request)
    {
        switch (request.TargetKind)
        {
            case ScanTargetKind.Repository:
                return;
            case ScanTargetKind.CommittedDiff:
                arguments.Add("--diff");
                arguments.Add(request.BaseRevision!.Trim());
                arguments.Add("--head");
                arguments.Add(request.HeadRevision.Trim());
                return;
            case ScanTargetKind.WorkingTree:
                arguments.Add("--working-tree");
                arguments.Add("--base");
                arguments.Add(request.BaseRevision!.Trim());
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(request));
        }
    }

    private static void AppendRepeatedPath(
        List<string> arguments,
        string option,
        string repository,
        IReadOnlyList<string> paths,
        bool requireInsideRepository = true)
    {
        foreach (var rawPath in paths)
        {
            var path = PathPolicy.Canonical(rawPath, option);
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                throw new ArgumentException($"{option} path does not exist.");
            }
            if (requireInsideRepository && !PathPolicy.IsEqualOrNested(path, repository))
            {
                throw new ArgumentException($"{option} path must be inside the repository.");
            }

            arguments.Add(option);
            arguments.Add(
                requireInsideRepository
                    ? Path.GetRelativePath(repository, path).Replace('\\', '/')
                    : path);
        }
    }
}
