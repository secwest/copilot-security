using System.Net;
using Secwest.Benchmarks.Services;

var handler = new RecordingHandler("public-logo");
using var client = new HttpClient(handler);
var preview = new PreviewClient(client);
const string attackerTarget = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";

try
{
    await preview.FetchAsync(attackerTarget, CancellationToken.None);
    throw new InvalidOperationException("Expected the unrecognized destination to fail closed.");
}
catch (KeyNotFoundException)
{
    // Expected: an arbitrary URL is not an authorized asset identifier.
}

if (handler.RequestedUris.Count != 0)
{
    throw new InvalidOperationException("The rejected attacker URL reached the outbound handler.");
}

var body = await preview.FetchAsync("logo", CancellationToken.None);
if (
    body != "public-logo"
    || handler.RequestedUris.Count != 1
    || handler.RequestedUris[0].AbsoluteUri != "https://cdn.example.invalid/assets/logo.svg"
)
{
    throw new InvalidOperationException("Expected the exact asset key to select the fixed CDN URI.");
}

Console.WriteLine("Safe SSRF witness rejected the attacker URI and selected one fixed CDN destination.");

internal sealed class RecordingHandler(string body) : HttpMessageHandler
{
    public List<Uri> RequestedUris { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        if (request.RequestUri is not null)
        {
            RequestedUris.Add(request.RequestUri);
        }

        return Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            }
        );
    }
}
