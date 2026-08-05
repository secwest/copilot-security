using Microsoft.AspNetCore.Mvc.RazorPages;
using Secwest.Benchmarks.Services;

namespace Secwest.Benchmarks.Pages;

public sealed class SearchModel : PageModel
{
    private readonly UserQueries _queries;

    public SearchModel(UserQueries queries)
    {
        _queries = queries;
    }

    public string? Result { get; private set; }

    public async Task OnGetLookupAsync(string filter)
    {
        Result = await _queries.LookupAsync(filter);
    }
}
