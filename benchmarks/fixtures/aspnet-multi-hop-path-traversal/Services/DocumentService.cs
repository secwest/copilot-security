namespace Secwest.Benchmarks.Services;

public sealed class DocumentService
{
    private readonly DocumentStore _store;

    public DocumentService(DocumentStore store)
    {
        _store = store;
    }

    public Task<string> ReadAsync(string path, CancellationToken cancellationToken)
    {
        return _store.ReadAsync(path, cancellationToken);
    }
}
