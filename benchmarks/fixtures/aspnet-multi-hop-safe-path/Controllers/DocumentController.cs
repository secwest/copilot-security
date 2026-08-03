using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Controllers;

[ApiController]
[Route("api/documents")]
public sealed class DocumentController : ControllerBase
{
    private readonly DocumentService _documents;

    public DocumentController(DocumentService documents)
    {
        _documents = documents;
    }

    [HttpGet]
    public async Task<IActionResult> Get(
        [FromQuery] string path,
        CancellationToken cancellationToken
    )
    {
        var document = await _documents.ReadAsync(path, cancellationToken);
        return Content(document, "text/plain");
    }
}
