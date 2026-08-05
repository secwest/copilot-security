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
if (page.Result != "Administrator")
{
    throw new InvalidOperationException(
        $"Expected the injected Razor Page handler value to select Administrator; received {page.Result ?? "null"}."
    );
}

Console.WriteLine("Vulnerable Razor Page SQL witness selected Administrator.");
