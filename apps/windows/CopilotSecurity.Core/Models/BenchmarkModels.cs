namespace Secwest.CopilotSecurity.Core.Models;

public sealed record BenchmarkMetricDelta(
    string Metric,
    double Baseline,
    double Candidate,
    double Delta,
    bool HigherIsBetter,
    bool Regressed);

public sealed record BenchmarkCaseDelta(
    string CaseId,
    bool BaselinePassed,
    bool CandidatePassed,
    int BaselineTruePositives,
    int CandidateTruePositives,
    int BaselineFalsePositives,
    int CandidateFalsePositives,
    int BaselineFalseNegatives,
    int CandidateFalseNegatives,
    bool Regressed);

public sealed record BenchmarkComparison(
    string BaselinePath,
    string CandidatePath,
    DateTimeOffset ComparedAt,
    double BaselineQualityIndex,
    double CandidateQualityIndex,
    IReadOnlyList<BenchmarkMetricDelta> Metrics,
    IReadOnlyList<BenchmarkCaseDelta> Cases,
    IReadOnlyList<string> Regressions,
    string Markdown)
{
    public bool Passed => Regressions.Count == 0;
}
