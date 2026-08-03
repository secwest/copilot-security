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

    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        _runner.Ping(host);
        return Accepted();
    }
}
