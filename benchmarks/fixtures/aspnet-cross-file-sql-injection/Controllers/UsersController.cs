using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Controllers;

[ApiController]
[Route("api/users")]
public sealed class UsersController : ControllerBase
{
    private readonly UserQueries _queries;

    public UsersController(UserQueries queries)
    {
        _queries = queries;
    }

    [HttpGet("lookup")]
    public async Task<IActionResult> Lookup([FromQuery] string name)
    {
        return Ok(await _queries.LookupAsync(name));
    }
}
