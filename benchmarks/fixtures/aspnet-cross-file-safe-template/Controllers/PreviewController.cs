using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Controllers;

[ApiController]
[Route("api/preview")]
public sealed class PreviewController : ControllerBase
{
    private readonly TemplateRenderer _renderer;

    public PreviewController(TemplateRenderer renderer)
    {
        _renderer = renderer;
    }

    [HttpPost]
    public IActionResult Render([FromBody] string name)
    {
        return Content(_renderer.Render(name), "text/html");
    }
}
