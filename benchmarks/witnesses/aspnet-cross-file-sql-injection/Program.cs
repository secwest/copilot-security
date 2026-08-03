using Microsoft.Data.SqlClient;

await using var connection = new SqlConnection("benchmark-in-memory");
await connection.OpenAsync();
const string attackerName = "' OR '1'='1";
await using var command = new SqlCommand(
    "SELECT DisplayName FROM Users WHERE Name = '" + attackerName + "'",
    connection
);
var result = (string?)await command.ExecuteScalarAsync();
if (result != "Administrator")
{
    throw new InvalidOperationException(
        $"Expected the injected predicate to select Administrator; received {result ?? "null"}."
    );
}

Console.WriteLine("Vulnerable SQL witness selected Administrator.");
