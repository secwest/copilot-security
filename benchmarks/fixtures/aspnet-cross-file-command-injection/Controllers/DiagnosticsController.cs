using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Controllers;

[ApiController]
[Route("api/diagnostics")]
public sealed class DiagnosticsController : ControllerBase
{
    private readonly CommandRunner _runner;

    public DiagnosticsController(CommandRunner runner)
    {
        _runner = runner;
    }

    [HttpGet("run")]
    public IActionResult Run([FromQuery] string command)
    {
        _runner.Run(command);
        return Accepted();
    }
}
