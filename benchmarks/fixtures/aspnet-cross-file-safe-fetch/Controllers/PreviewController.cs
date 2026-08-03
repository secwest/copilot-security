using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Controllers;

[ApiController]
[Route("api/preview")]
public sealed class PreviewController : ControllerBase
{
    private readonly PreviewClient _preview;

    public PreviewController(PreviewClient preview)
    {
        _preview = preview;
    }

    [HttpGet]
    public async Task<IActionResult> Get(
        [FromQuery] string asset,
        CancellationToken cancellationToken
    )
    {
        var body = await _preview.FetchAsync(asset, cancellationToken);
        return Content(body, "text/plain");
    }
}
