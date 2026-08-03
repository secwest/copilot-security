using Secwest.Benchmarks.Services;

var witnessRoot = Path.Combine(Path.GetTempPath(), $"copilot-security-path-{Guid.NewGuid():N}");
var contentRoot = Path.Combine(witnessRoot, "public");
var privateRoot = Path.Combine(witnessRoot, "private");
var secretPath = Path.Combine(privateRoot, "deployment-secret.txt");

try
{
    Directory.CreateDirectory(contentRoot);
    Directory.CreateDirectory(privateRoot);
    await File.WriteAllTextAsync(secretPath, "deployment-secret");
    var store = new DocumentStore(contentRoot);

    var traversed = await store.ReadAsync(
        Path.Combine("..", "private", "deployment-secret.txt"),
        CancellationToken.None
    );
    var absoluteReset = await store.ReadAsync(secretPath, CancellationToken.None);
    if (traversed != "deployment-secret" || absoluteReset != "deployment-secret")
    {
        throw new InvalidOperationException(
            "Expected parent traversal and rooted-path reset to read the private file."
        );
    }

    Console.WriteLine(
        "Vulnerable path witness escaped the content root by parent traversal and rooted-path reset."
    );
}
finally
{
    Directory.Delete(witnessRoot, recursive: true);
}
