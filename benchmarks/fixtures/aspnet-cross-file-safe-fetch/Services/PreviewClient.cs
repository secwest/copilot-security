using System.Text;

namespace Secwest.Benchmarks.Services;

public sealed class PreviewClient
{
    private const int MaxBodyBytes = 4096;
    private static readonly IReadOnlyDictionary<string, Uri> AssetUrls =
        new Dictionary<string, Uri>(StringComparer.Ordinal)
        {
            ["logo"] = new Uri("https://cdn.example.invalid/assets/logo.svg"),
            ["style"] = new Uri("https://cdn.example.invalid/assets/site.css"),
        };

    private readonly HttpClient _client;

    public PreviewClient(HttpClient client)
    {
        _client = client;
    }

    public async Task<string> FetchAsync(string asset, CancellationToken cancellationToken)
    {
        if (!AssetUrls.TryGetValue(asset, out var target))
        {
            throw new KeyNotFoundException("Unknown asset identifier.");
        }

        using var response = await _client.GetAsync(
            target,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken
        );
        response.EnsureSuccessStatusCode();
        return await ReadBoundedBodyAsync(response, cancellationToken);
    }

    private static async Task<string> ReadBoundedBodyAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken
    )
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[MaxBodyBytes + 1];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(count), cancellationToken);
            if (read == 0)
            {
                break;
            }

            count += read;
        }

        if (count > MaxBodyBytes)
        {
            throw new InvalidOperationException("Upstream response exceeded the preview limit.");
        }

        return Encoding.UTF8.GetString(buffer, 0, count);
    }
}
