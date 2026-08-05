using Microsoft.Extensions.Configuration;
using Secwest.Benchmarks.Pages;
using Secwest.Benchmarks.Services;

var configuration = new ConfigurationBuilder()
    .AddInMemoryCollection(
        new Dictionary<string, string?>
        {
            ["ConnectionStrings:App"] = "benchmark-in-memory",
        }
    )
    .Build();
var page = new SearchModel(new UserQueries(configuration));
const string attackerFilter = "' OR '1'='1";
await page.OnGetLookupAsync(attackerFilter);
if (page.Result is not null)
{
    throw new InvalidOperationException(
        $"Expected the parameterized Razor Page query to reject the injected value; received {page.Result}."
    );
}

await page.OnGetLookupAsync("alice");
if (page.Result != "Alice")
{
    throw new InvalidOperationException(
        $"Expected the parameterized Razor Page query to preserve the exact value; received {page.Result ?? "null"}."
    );
}

Console.WriteLine("Safe Razor Page SQL witness rejected injection and selected Alice exactly.");
