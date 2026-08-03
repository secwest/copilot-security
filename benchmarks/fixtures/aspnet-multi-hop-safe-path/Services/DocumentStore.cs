using System.IO;

namespace Secwest.Benchmarks.Services;

public sealed class DocumentStore
{
    private readonly string _contentRoot;

    public DocumentStore(string contentRoot)
    {
        _contentRoot = contentRoot;
    }

    public Task<string> ReadAsync(string path, CancellationToken cancellationToken)
    {
        var resolvedPath = ResolveUnderContentRoot(path);
        return File.ReadAllTextAsync(resolvedPath, cancellationToken);
    }

    private string ResolveUnderContentRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || Path.IsPathRooted(path))
        {
            throw new UnauthorizedAccessException("A relative document path is required.");
        }

        var canonicalRoot = Path.GetFullPath(_contentRoot);
        var canonicalCandidate = Path.GetFullPath(Path.Combine(canonicalRoot, path));
        var relativeCandidate = Path.GetRelativePath(canonicalRoot, canonicalCandidate);
        if (
            relativeCandidate.Equals("..", StringComparison.Ordinal)
            || relativeCandidate.StartsWith(
                $"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal
            )
            || Path.IsPathRooted(relativeCandidate)
        )
        {
            throw new UnauthorizedAccessException("The document path escapes the content root.");
        }

        return canonicalCandidate;
    }
}
