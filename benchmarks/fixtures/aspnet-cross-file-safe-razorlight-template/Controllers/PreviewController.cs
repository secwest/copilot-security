using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Controllers;

[ApiController]
[Route("preview")]
public sealed class PreviewController : ControllerBase
{
    private readonly RazorTemplateRenderer _renderer;

    public PreviewController(RazorTemplateRenderer renderer)
    {
        _renderer = renderer;
    }

    [HttpPost]
    public Task<string> Preview([FromBody] string name)
    {
        return _renderer.RenderAsync(name);
    }
}
