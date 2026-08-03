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
        return File.ReadAllTextAsync(Path.Combine(_contentRoot, path), cancellationToken);
    }
}
