namespace Secwest.Benchmarks.Services;

public sealed class DocumentFacade
{
    private readonly DocumentService _service;

    public DocumentFacade(DocumentService service)
    {
        _service = service;
    }

    public Task<string> ReadAsync(string path, CancellationToken cancellationToken)
    {
        return _service.ReadAsync(path, cancellationToken);
    }
}
