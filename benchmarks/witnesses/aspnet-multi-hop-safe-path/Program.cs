using Secwest.Benchmarks.Services;

var witnessRoot = Path.Combine(
    Path.GetTempPath(),
    $"copilot-security-safe-path-{Guid.NewGuid():N}"
);
var contentRoot = Path.Combine(witnessRoot, "public");
var privateRoot = Path.Combine(witnessRoot, "private");
var siblingRoot = Path.Combine(witnessRoot, "public-backup");
var secretPath = Path.Combine(privateRoot, "deployment-secret.txt");
var siblingSecretPath = Path.Combine(siblingRoot, "sibling-secret.txt");

try
{
    Directory.CreateDirectory(contentRoot);
    Directory.CreateDirectory(privateRoot);
    Directory.CreateDirectory(siblingRoot);
    await File.WriteAllTextAsync(Path.Combine(contentRoot, "guide.txt"), "public-guide");
    await File.WriteAllTextAsync(secretPath, "deployment-secret");
    await File.WriteAllTextAsync(siblingSecretPath, "sibling-secret");
    var store = new DocumentStore(contentRoot);

    var guide = await store.ReadAsync("guide.txt", CancellationToken.None);
    if (guide != "public-guide")
    {
        throw new InvalidOperationException("Expected an in-root document to remain readable.");
    }

    await ExpectRejectedAsync(
        store,
        Path.Combine("..", "private", "deployment-secret.txt")
    );
    await ExpectRejectedAsync(store, secretPath);
    await ExpectRejectedAsync(
        store,
        Path.Combine("..", "public-backup", "sibling-secret.txt")
    );

    Console.WriteLine(
        "Safe path witness allowed an in-root file and rejected parent, absolute, and sibling-prefix escapes."
    );
}
finally
{
    Directory.Delete(witnessRoot, recursive: true);
}

static async Task ExpectRejectedAsync(DocumentStore store, string path)
{
    try
    {
        await store.ReadAsync(path, CancellationToken.None);
        throw new InvalidOperationException($"Expected the path to be rejected: {path}");
    }
    catch (UnauthorizedAccessException)
    {
        // Expected: resolution rejected the path before File.ReadAllTextAsync.
    }
}
