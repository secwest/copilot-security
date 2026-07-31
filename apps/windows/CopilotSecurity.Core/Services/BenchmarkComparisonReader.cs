using System.Globalization;
using System.Text;
using System.Text.Json;
using Secwest.CopilotSecurity.Core.Models;

namespace Secwest.CopilotSecurity.Core.Services;

public sealed class BenchmarkComparisonReader
{
    private const long MaximumReportBytes = 64 * 1024 * 1024;
    private const double RegressionTolerance = 0.001;
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 256,
    };
    private static readonly (string Name, bool HigherIsBetter, double Weight)[] Metrics =
    [
        ("completionRate", true, 0.12),
        ("precision", true, 0.14),
        ("recall", true, 0.16),
        ("f1", true, 0.12),
        ("casePassRate", true, 0.08),
        ("negativeCasePassRate", true, 0.08),
        ("stableDetectionRate", true, 0.10),
        ("validationRate", true, 0.05),
        ("attackPathRate", true, 0.05),
        ("codeEvidenceRate", true, 0.04),
        ("severityAccuracy", true, 0.03),
        ("falsePositivesPerRun", false, 0.03),
    ];

    public async Task<BenchmarkComparison> CompareAsync(
        string baselinePath,
        string candidatePath,
        CancellationToken cancellationToken = default)
    {
        var baseline = await ReadAsync(baselinePath, cancellationToken).ConfigureAwait(false);
        var candidate = await ReadAsync(candidatePath, cancellationToken).ConfigureAwait(false);

        if (baseline.CaseCount != candidate.CaseCount || baseline.RunCount != candidate.RunCount)
        {
            throw new InvalidDataException(
                "Benchmark reports must cover the same number of cases and runs.");
        }
        if (!baseline.Cases.Keys.Order(StringComparer.Ordinal).SequenceEqual(
            candidate.Cases.Keys.Order(StringComparer.Ordinal),
            StringComparer.Ordinal))
        {
            throw new InvalidDataException("Benchmark reports must cover exactly the same case IDs.");
        }
        if ((baseline.CorpusId is null) != (candidate.CorpusId is null))
        {
            throw new InvalidDataException(
                "Benchmark reports must both include campaign provenance or both be legacy reports.");
        }
        if (baseline.CorpusId is not null &&
            (!StringComparer.Ordinal.Equals(baseline.CorpusId, candidate.CorpusId) ||
             !StringComparer.Ordinal.Equals(baseline.ScanPolicyId, candidate.ScanPolicyId)))
        {
            throw new InvalidDataException(
                "Benchmark reports must use the same corpus bytes, case/run selection, and scan policy.");
        }
        foreach (var caseId in baseline.Cases.Keys)
        {
            var before = baseline.Cases[caseId];
            var after = candidate.Cases[caseId];
            if (before.ExpectedCount != after.ExpectedCount || before.RunCount != after.RunCount)
            {
                throw new InvalidDataException(
                    $"Benchmark case {caseId} must use the same expectations and run count.");
            }
        }

        var metricDeltas = Metrics.Select(metric =>
        {
            var before = baseline.Metrics[metric.Name];
            var after = candidate.Metrics[metric.Name];
            var regressed = metric.HigherIsBetter
                ? after + RegressionTolerance < before
                : after - RegressionTolerance > before;
            return new BenchmarkMetricDelta(
                metric.Name,
                before,
                after,
                after - before,
                metric.HigherIsBetter,
                regressed);
        }).ToArray();

        var caseDeltas = baseline.Cases.Keys.Order(StringComparer.Ordinal).Select(caseId =>
        {
            var before = baseline.Cases[caseId];
            var after = candidate.Cases[caseId];
            var regressed = before.Passed && !after.Passed ||
                after.TruePositives < before.TruePositives ||
                after.FalsePositives > before.FalsePositives ||
                after.FalseNegatives > before.FalseNegatives;
            return new BenchmarkCaseDelta(
                caseId,
                before.Passed,
                after.Passed,
                before.TruePositives,
                after.TruePositives,
                before.FalsePositives,
                after.FalsePositives,
                before.FalseNegatives,
                after.FalseNegatives,
                regressed);
        }).ToArray();

        var regressions = metricDeltas.Where(delta => delta.Regressed)
            .Select(delta => $"Metric regressed: {delta.Metric} ({Format(delta.Baseline)} → {Format(delta.Candidate)}).")
            .Concat(caseDeltas.Where(delta => delta.Regressed)
                .Select(delta => $"Case regressed: {delta.CaseId}."))
            .ToArray();
        var baselineScore = QualityIndex(baseline.Metrics);
        var candidateScore = QualityIndex(candidate.Metrics);
        var comparedAt = DateTimeOffset.UtcNow;
        var markdown = RenderMarkdown(
            baseline.Path,
            candidate.Path,
            comparedAt,
            baselineScore,
            candidateScore,
            metricDeltas,
            caseDeltas,
            regressions);

        return new BenchmarkComparison(
            baseline.Path,
            candidate.Path,
            comparedAt,
            baselineScore,
            candidateScore,
            metricDeltas,
            caseDeltas,
            regressions,
            markdown);
    }

    private static async Task<Snapshot> ReadAsync(string path, CancellationToken cancellationToken)
    {
        var canonical = PathPolicy.ExistingFile(path, "Benchmark report");
        var information = new FileInfo(canonical);
        if ((information.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Benchmark report must not be a reparse point.");
        }
        if (information.Length > MaximumReportBytes)
        {
            throw new InvalidDataException("Benchmark report exceeds the 64 MiB limit.");
        }

        await using var stream = new FileStream(
            canonical,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var document = await JsonDocument.ParseAsync(
            stream,
            JsonOptions,
            cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;
        var documentType = RequiredString(root, "documentType");
        if (!IsBenchmarkDocumentType(documentType) || RequiredString(root, "schemaVersion") != "1.0")
        {
            throw new InvalidDataException("Unsupported benchmark report type or schema version.");
        }
        var metricsElement = RequiredObject(root, "metrics");
        var metrics = Metrics.ToDictionary(
            metric => metric.Name,
            metric => RequiredNumber(metricsElement, metric.Name),
            StringComparer.Ordinal);
        var caseCount = RequiredInteger(metricsElement, "caseCount");
        var runCount = RequiredInteger(metricsElement, "runCount");
        var casesElement = RequiredArray(root, "cases");
        var cases = new Dictionary<string, CaseSnapshot>(StringComparer.Ordinal);
        var countedRuns = 0;
        foreach (var item in casesElement.EnumerateArray())
        {
            var id = RequiredString(item, "id");
            var runs = RequiredArray(item, "runs");
            var runItems = runs.EnumerateArray().ToArray();
            countedRuns += runItems.Length;
            var truePositives = 0;
            var falsePositives = 0;
            var falseNegatives = 0;
            foreach (var run in runItems)
            {
                truePositives += RequiredInteger(run, "truePositives");
                falsePositives += RequiredInteger(run, "falsePositives");
                falseNegatives += RequiredInteger(run, "falseNegatives");
            }
            if (!cases.TryAdd(
                id,
                new CaseSnapshot(
                    RequiredBoolean(item, "passed"),
                    RequiredInteger(item, "expectedCount"),
                    runItems.Length,
                    truePositives,
                    falsePositives,
                    falseNegatives)))
            {
                throw new InvalidDataException("Benchmark report contains a duplicate case ID.");
            }
        }
        if (cases.Count != caseCount)
        {
            throw new InvalidDataException("Benchmark case count does not match its metrics.");
        }
        if (countedRuns != runCount)
        {
            throw new InvalidDataException("Benchmark run count does not match its metrics.");
        }
        var (corpusId, scanPolicyId) = OptionalCampaignIdentity(root);
        return new Snapshot(
            canonical,
            caseCount,
            runCount,
            corpusId,
            scanPolicyId,
            metrics,
            cases);
    }

    private static bool IsBenchmarkDocumentType(string value) =>
        value.Length <= 128 &&
        value.EndsWith(".benchmark", StringComparison.Ordinal) &&
        value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');

    private static (string? CorpusId, string? ScanPolicyId) OptionalCampaignIdentity(
        JsonElement root)
    {
        if (!root.TryGetProperty("campaign", out var campaign))
        {
            return (null, null);
        }
        if (campaign.ValueKind != JsonValueKind.Object ||
            RequiredString(campaign, "documentType") != "copilot-security.benchmark-campaign" ||
            RequiredString(campaign, "schemaVersion") != "1.0")
        {
            throw new InvalidDataException("Benchmark campaign provenance is invalid.");
        }
        var corpusId = RequiredString(campaign, "corpusId");
        var scanPolicyId = RequiredString(campaign, "scanPolicyId");
        if (!IsSha256(corpusId) || !IsSha256(scanPolicyId))
        {
            throw new InvalidDataException(
                "Benchmark campaign corpus and scan-policy IDs must be lowercase SHA-256 values.");
        }
        return (corpusId, scanPolicyId);
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static double QualityIndex(IReadOnlyDictionary<string, double> metrics)
    {
        var total = 0.0;
        foreach (var metric in Metrics)
        {
            var value = metrics[metric.Name];
            var normalized = metric.HigherIsBetter
                ? Math.Clamp(value, 0, 1)
                : 1 - Math.Clamp(value, 0, 1);
            total += normalized * metric.Weight;
        }
        return total;
    }

    private static string RenderMarkdown(
        string baselinePath,
        string candidatePath,
        DateTimeOffset comparedAt,
        double baselineScore,
        double candidateScore,
        IReadOnlyList<BenchmarkMetricDelta> metrics,
        IReadOnlyList<BenchmarkCaseDelta> cases,
        IReadOnlyList<string> regressions)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Scanner effectiveness comparison");
        builder.AppendLine();
        builder.AppendLine($"Compared: {comparedAt:O}");
        builder.AppendLine();
        builder.AppendLine($"- Baseline: `{baselinePath}`");
        builder.AppendLine($"- Candidate: `{candidatePath}`");
        builder.AppendLine($"- Quality index: {Format(baselineScore)} → {Format(candidateScore)} ({Format(candidateScore - baselineScore, signed: true)})");
        builder.AppendLine($"- Regression gate: {(regressions.Count == 0 ? "PASS" : "FAIL")}");
        builder.AppendLine();
        builder.AppendLine("The quality index is a transparent weighted summary; the per-metric and per-case gates remain authoritative.");
        builder.AppendLine();
        builder.AppendLine("| Metric | Baseline | Candidate | Delta | Direction | Gate |");
        builder.AppendLine("| --- | ---: | ---: | ---: | --- | --- |");
        foreach (var metric in metrics)
        {
            builder.AppendLine($"| {metric.Metric} | {Format(metric.Baseline)} | {Format(metric.Candidate)} | {Format(metric.Delta, signed: true)} | {(metric.HigherIsBetter ? "higher" : "lower")} | {(metric.Regressed ? "FAIL" : "PASS")} |");
        }
        builder.AppendLine();
        if (regressions.Count > 0)
        {
            builder.AppendLine("## Regressions");
            builder.AppendLine();
            foreach (var regression in regressions)
            {
                builder.AppendLine("- " + regression);
            }
            builder.AppendLine();
        }
        var changedCases = cases.Where(item => item.Regressed ||
            item.BaselineTruePositives != item.CandidateTruePositives ||
            item.BaselineFalsePositives != item.CandidateFalsePositives ||
            item.BaselineFalseNegatives != item.CandidateFalseNegatives).ToArray();
        builder.AppendLine("## Changed cases");
        builder.AppendLine();
        if (changedCases.Length == 0)
        {
            builder.AppendLine("No per-case TP/FP/FN changes.");
        }
        else
        {
            builder.AppendLine("| Case | TP | FP | FN | Gate |");
            builder.AppendLine("| --- | ---: | ---: | ---: | --- |");
            foreach (var item in changedCases)
            {
                builder.AppendLine($"| {item.CaseId} | {item.BaselineTruePositives}→{item.CandidateTruePositives} | {item.BaselineFalsePositives}→{item.CandidateFalsePositives} | {item.BaselineFalseNegatives}→{item.CandidateFalseNegatives} | {(item.Regressed ? "FAIL" : "PASS")} |");
            }
        }
        return builder.ToString();
    }

    private static string Format(double value, bool signed = false) =>
        value.ToString(signed ? "+0.0000;-0.0000;0.0000" : "0.0000", CultureInfo.InvariantCulture);

    private static JsonElement RequiredObject(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Object
            ? value
            : throw new InvalidDataException($"Benchmark report field {name} must be an object.");

    private static JsonElement RequiredArray(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value
            : throw new InvalidDataException($"Benchmark report field {name} must be an array.");

    private static string RequiredString(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(value.GetString())
                ? value.GetString()!
                : throw new InvalidDataException($"Benchmark report field {name} must be a non-empty string.");

    private static double RequiredNumber(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.TryGetDouble(out var result) &&
            double.IsFinite(result) && result >= 0
                ? result
                : throw new InvalidDataException($"Benchmark report field {name} must be a finite non-negative number.");

    private static int RequiredInteger(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.TryGetInt32(out var result) && result >= 0
            ? result
            : throw new InvalidDataException($"Benchmark report field {name} must be a non-negative integer.");

    private static bool RequiredBoolean(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) &&
            (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False)
                ? value.GetBoolean()
                : throw new InvalidDataException($"Benchmark report field {name} must be boolean.");

    private sealed record Snapshot(
        string Path,
        int CaseCount,
        int RunCount,
        string? CorpusId,
        string? ScanPolicyId,
        IReadOnlyDictionary<string, double> Metrics,
        IReadOnlyDictionary<string, CaseSnapshot> Cases);

    private sealed record CaseSnapshot(
        bool Passed,
        int ExpectedCount,
        int RunCount,
        int TruePositives,
        int FalsePositives,
        int FalseNegatives);
}
