using System.Security.Cryptography;
using System.Text.Json;
using Secwest.CopilotSecurity.Core.Models;

namespace Secwest.CopilotSecurity.Core.Services;

public sealed class ScanArtifactReader
{
    private const long MaximumManifestBytes = 16 * 1024 * 1024;
    private const long MaximumFindingsBytes = 128 * 1024 * 1024;
    private const long MaximumCoverageBytes = 32 * 1024 * 1024;
    private const long MaximumReportBytes = 32 * 1024 * 1024;
    private const long MaximumSealedArtifactBytes = 256 * 1024 * 1024;
    private const long MaximumSealedArtifactAggregateBytes = 1024L * 1024 * 1024;
    private const int MaximumSealedArtifacts = 8_192;
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 256,
    };

    public async Task<ScanArtifacts> ReadAsync(
        string scanDirectory,
        CancellationToken cancellationToken = default)
    {
        var directory = PathPolicy.ExistingDirectory(scanDirectory, "Scan directory");
        var reportPath = SafeArtifactPath(directory, "report.md");
        var manifestPath = SafeArtifactPath(directory, "scan-manifest.json");
        var findingsPath = SafeArtifactPath(directory, "findings.json");
        var coveragePath = SafeArtifactPath(directory, "coverage.json");

        var report = await ReadBoundedTextAsync(
            reportPath,
            MaximumReportBytes,
            cancellationToken).ConfigureAwait(false);
        using var manifest = await ReadBoundedJsonAsync(
            manifestPath,
            MaximumManifestBytes,
            cancellationToken).ConfigureAwait(false);
        using var findings = await ReadBoundedJsonAsync(
            findingsPath,
            MaximumFindingsBytes,
            cancellationToken).ConfigureAwait(false);
        using var coverage = await ReadBoundedJsonAsync(
            coveragePath,
            MaximumCoverageBytes,
            cancellationToken).ConfigureAwait(false);

        RequireDocumentType(manifest.RootElement, "copilot-security.scan-manifest", "scan-manifest.json");
        RequireDocumentType(findings.RootElement, "copilot-security.findings", "findings.json");
        RequireDocumentType(coverage.RootElement, "copilot-security.coverage", "coverage.json");
        RequireSchemaVersion(manifest.RootElement, "scan-manifest.json");
        RequireSchemaVersion(findings.RootElement, "findings.json");
        RequireSchemaVersion(coverage.RootElement, "coverage.json");

        var scan = RequiredObject(manifest.RootElement, "scan", "scan-manifest.json");
        var scanId = RequiredString(scan, "id", "scan-manifest.json.scan");
        var status = RequiredString(scan, "status", "scan-manifest.json.scan");
        if (!status.Equals("completed", StringComparison.Ordinal))
        {
            throw new InvalidDataException("scan-manifest.json does not describe a completed scan.");
        }
        _ = RequiredObject(scan, "producer", "scan-manifest.json.scan");
        _ = RequiredObject(scan, "target", "scan-manifest.json.scan");
        _ = RequiredObject(scan, "scope", "scan-manifest.json.scan");
        var startedAt = RequiredDate(scan, "startedAt", "scan-manifest.json.scan");
        var completedAt = RequiredDate(scan, "completedAt", "scan-manifest.json.scan");
        var sealedAt = RequiredDate(scan, "sealedAt", "scan-manifest.json.scan");
        if (completedAt != sealedAt || completedAt < startedAt)
        {
            throw new InvalidDataException(
                "scan-manifest.json completion and sealing timestamps are inconsistent.");
        }
        RequireExactString(scan, "findingsRef", "findings.json", "scan-manifest.json.scan");
        RequireExactString(scan, "coverageRef", "coverage.json", "scan-manifest.json.scan");
        RequireExactString(findings.RootElement, "scanId", scanId, "findings.json");
        RequireExactString(coverage.RootElement, "scanId", scanId, "coverage.json");
        await VerifySealedArtifactsAsync(
            directory,
            scan,
            cancellationToken).ConfigureAwait(false);
        var coverageCompleteness = RequiredString(
            coverage.RootElement,
            "completeness",
            "coverage.json");
        var parsedFindings = ParseFindings(findings.RootElement);

        return new ScanArtifacts(
            directory,
            reportPath,
            manifestPath,
            findingsPath,
            coveragePath,
            scanId,
            status,
            coverageCompleteness,
            startedAt,
            completedAt,
            parsedFindings,
            report);
    }

    public async Task<IReadOnlyList<ScanHistoryItem>> ReadHistoryAsync(
        string guiRunsRoot,
        CancellationToken cancellationToken = default)
    {
        var root = PathPolicy.Canonical(guiRunsRoot, "GUI runs root");
        if (!Directory.Exists(root))
        {
            return [];
        }

        var results = new List<ScanHistoryItem>();
        foreach (var directory in Directory.EnumerateDirectories(root).Take(1_000))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0 ||
                !File.Exists(Path.Combine(directory, "scan-manifest.json")))
            {
                continue;
            }

            try
            {
                var artifacts = await ReadAsync(directory, cancellationToken).ConfigureAwait(false);
                using var manifest = await ReadBoundedJsonAsync(
                    artifacts.ManifestPath,
                    MaximumManifestBytes,
                    cancellationToken).ConfigureAwait(false);
                var scan = RequiredObject(manifest.RootElement, "scan", "scan-manifest.json");
                var target = RequiredObject(scan, "target", "scan-manifest.json.scan");
                var repository = target.TryGetProperty("displayName", out var displayName) &&
                    displayName.ValueKind == JsonValueKind.String
                        ? displayName.GetString() ?? Path.GetFileName(directory)
                        : Path.GetFileName(directory);
                results.Add(
                    new ScanHistoryItem(
                        directory,
                        artifacts.ScanId,
                        repository,
                        artifacts.Status,
                        artifacts.CoverageCompleteness,
                        artifacts.Findings.Count,
                        artifacts.CompletedAt));
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or JsonException)
            {
                // A malformed or incomplete run is not presented as a completed history item.
            }
        }

        return results
            .OrderByDescending(item => item.CompletedAt)
            .ThenBy(item => item.ScanId, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<ScanFinding> ParseFindings(JsonElement root)
    {
        if (!root.TryGetProperty("findings", out var findings) ||
            findings.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("findings.json.findings must be an array.");
        }

        var result = new List<ScanFinding>();
        foreach (var finding in findings.EnumerateArray())
        {
            var taxonomy = RequiredObject(finding, "taxonomy", "finding");
            var severity = RequiredObject(finding, "severity", "finding");
            var confidence = RequiredObject(finding, "confidence", "finding");
            var validation = RequiredObject(finding, "validation", "finding");
            var attackPath = RequiredObject(finding, "attackPath", "finding");
            var cwes = taxonomy.TryGetProperty("cwe", out var cweArray) &&
                cweArray.ValueKind == JsonValueKind.Array
                    ? cweArray.EnumerateArray()
                        .Where(value => value.ValueKind == JsonValueKind.String)
                        .Select(value => value.GetString() ?? string.Empty)
                        .Where(value => value.Length > 0)
                        .ToArray()
                    : [];
            var locations = finding.TryGetProperty("locations", out var locationArray) &&
                locationArray.ValueKind == JsonValueKind.Array
                    ? locationArray.EnumerateArray().Select(ParseLocation).ToArray()
                    : [];

            result.Add(
                new ScanFinding(
                    RequiredString(finding, "findingId", "finding"),
                    RequiredString(finding, "title", "finding"),
                    RequiredString(finding, "summary", "finding"),
                    RequiredString(severity, "level", "finding.severity"),
                    RequiredString(confidence, "level", "finding.confidence"),
                    RequiredString(taxonomy, "category", "finding.taxonomy"),
                    cwes,
                    locations,
                    JsonSummary(validation),
                    JsonSummary(attackPath),
                    OptionalString(finding, "remediation")));
        }

        return result;
    }

    private static FindingLocation ParseLocation(JsonElement location) =>
        new(
            RequiredString(location, "path", "finding.location"),
            RequiredInt(location, "startLine", "finding.location"),
            location.TryGetProperty("endLine", out var endLine) && endLine.TryGetInt32(out var end)
                ? end
                : null,
            OptionalString(location, "role"));

    private static string JsonSummary(JsonElement value)
    {
        foreach (var property in new[] { "summary", "exploitWitness", "outcome" })
        {
            var text = OptionalString(value, property);
            if (text.Length > 0)
            {
                return text;
            }
        }
        return value.GetRawText();
    }

    private static string SafeArtifactPath(string directory, string name)
    {
        if (Path.IsPathRooted(name))
        {
            throw new InvalidDataException($"Required scan artifact has an unsafe path: {name}");
        }
        var path = Path.GetFullPath(Path.Combine(directory, name));
        if (!PathPolicy.IsEqualOrNested(path, directory) || !File.Exists(path))
        {
            throw new InvalidDataException($"Required scan artifact is missing: {name}");
        }
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Required scan artifact must not be a reparse point: {name}");
        }
        var relative = Path.GetRelativePath(directory, path);
        var components = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        var parent = directory;
        foreach (var component in components.Take(Math.Max(0, components.Length - 1)))
        {
            parent = Path.Combine(parent, component);
            if (!Directory.Exists(parent) ||
                (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Required scan artifact has an unsafe parent directory: {name}");
            }
        }
        return path;
    }

    private static async Task<string> ReadBoundedTextAsync(
        string path,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        var information = new FileInfo(path);
        if (information.Length > maximumBytes)
        {
            throw new InvalidDataException($"{information.Name} exceeds the {maximumBytes}-byte limit.");
        }
        return await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<JsonDocument> ReadBoundedJsonAsync(
        string path,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        var information = new FileInfo(path);
        if (information.Length > maximumBytes)
        {
            throw new InvalidDataException($"{information.Name} exceeds the {maximumBytes}-byte limit.");
        }
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await JsonDocument.ParseAsync(
            stream,
            JsonOptions,
            cancellationToken).ConfigureAwait(false);
    }

    private static JsonElement RequiredObject(JsonElement parent, string name, string context)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{context}.{name} must be an object.");
        }
        return value;
    }

    private static void RequireDocumentType(JsonElement root, string expected, string context)
    {
        if (!root.TryGetProperty("documentType", out var value) ||
            value.ValueKind != JsonValueKind.String ||
            !string.Equals(value.GetString(), expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{context} has an unsupported document type.");
        }
    }

    private static async Task VerifySealedArtifactsAsync(
        string directory,
        JsonElement scan,
        CancellationToken cancellationToken)
    {
        if (!scan.TryGetProperty("artifacts", out var artifacts) ||
            artifacts.ValueKind != JsonValueKind.Array ||
            artifacts.GetArrayLength() == 0 ||
            artifacts.GetArrayLength() > MaximumSealedArtifacts)
        {
            throw new InvalidDataException(
                $"scan-manifest.json.scan.artifacts must contain 1 to {MaximumSealedArtifacts} entries.");
        }

        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        var paths = new HashSet<string>(comparer);
        long aggregateBytes = 0;
        foreach (var artifact in artifacts.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = RequiredString(artifact, "path", "scan-manifest.json.scan.artifact");
            _ = RequiredString(artifact, "mediaType", "scan-manifest.json.scan.artifact");
            if (Path.IsPathRooted(relativePath) ||
                relativePath.Contains('\\') ||
                relativePath.Split('/').Any(part => part.Length == 0 || part is "." or ".."))
            {
                throw new InvalidDataException(
                    $"Sealed artifact path is not a safe repository-relative path: {relativePath}");
            }
            if (!paths.Add(relativePath))
            {
                throw new InvalidDataException($"Duplicate sealed artifact path: {relativePath}");
            }
            var expectedHex = RequiredString(artifact, "sha256", "scan-manifest.json.scan.artifact");
            if (expectedHex.Length != 64 || !expectedHex.All(Uri.IsHexDigit))
            {
                throw new InvalidDataException(
                    $"scan-manifest.json has an invalid SHA-256 for {relativePath}.");
            }
            var artifactPath = SafeArtifactPath(directory, relativePath);
            var information = new FileInfo(artifactPath);
            if (information.Length > MaximumSealedArtifactBytes)
            {
                throw new InvalidDataException(
                    $"Sealed artifact {relativePath} exceeds the {MaximumSealedArtifactBytes}-byte limit.");
            }
            if (information.Length > MaximumSealedArtifactAggregateBytes - aggregateBytes)
            {
                throw new InvalidDataException(
                    $"Sealed artifacts exceed the {MaximumSealedArtifactAggregateBytes}-byte aggregate limit.");
            }
            aggregateBytes += information.Length;

            await using var stream = new FileStream(
                artifactPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var actual = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            var expected = Convert.FromHexString(expectedHex);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                throw new InvalidDataException(
                    $"{relativePath} does not match its sealed manifest digest.");
            }
        }
        foreach (var required in new[] { "findings.json", "coverage.json", "report.md" })
        {
            if (!paths.Contains(required))
            {
                throw new InvalidDataException(
                    $"scan-manifest.json does not seal required artifact {required}.");
            }
        }
    }

    private static void RequireSchemaVersion(JsonElement root, string context) =>
        RequireExactString(root, "schemaVersion", "1.0", context);

    private static void RequireExactString(
        JsonElement parent,
        string name,
        string expected,
        string context)
    {
        if (!RequiredString(parent, name, context).Equals(expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{context}.{name} must equal {expected}.");
        }
    }

    private static string RequiredString(JsonElement parent, string name, string context)
    {
        var value = OptionalString(parent, name);
        if (value.Length == 0)
        {
            throw new InvalidDataException($"{context}.{name} must be a non-empty string.");
        }
        return value;
    }

    private static string OptionalString(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static int RequiredInt(JsonElement parent, string name, string context)
    {
        if (!parent.TryGetProperty(name, out var value) || !value.TryGetInt32(out var result))
        {
            throw new InvalidDataException($"{context}.{name} must be an integer.");
        }
        return result;
    }

    private static DateTimeOffset? OptionalDate(JsonElement parent, string name) =>
        DateTimeOffset.TryParse(
            OptionalString(parent, name),
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind,
            out var result)
            ? result
            : null;

    private static DateTimeOffset RequiredDate(JsonElement parent, string name, string context) =>
        OptionalDate(parent, name) ??
        throw new InvalidDataException($"{context}.{name} must be an ISO-8601 timestamp.");
}
