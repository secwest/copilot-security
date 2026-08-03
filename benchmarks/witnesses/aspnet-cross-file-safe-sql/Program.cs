using System.Data;
using Microsoft.Data.SqlClient;

await using var connection = new SqlConnection("benchmark-in-memory");
await connection.OpenAsync();
await using var command = new SqlCommand(
    "SELECT DisplayName FROM Users WHERE Name = @name",
    connection
);
command.Parameters.Add(
    new SqlParameter("@name", SqlDbType.NVarChar, 128) { Value = "' OR '1'='1" }
);
var injectedResult = (string?)await command.ExecuteScalarAsync();
if (injectedResult is not null)
{
    throw new InvalidOperationException(
        $"Expected the injected parameter to match no user; received {injectedResult}."
    );
}

await using var exactCommand = new SqlCommand(
    "SELECT DisplayName FROM Users WHERE Name = @name",
    connection
);
exactCommand.Parameters.Add(
    new SqlParameter("@name", SqlDbType.NVarChar, 128) { Value = "alice" }
);
var exactResult = (string?)await exactCommand.ExecuteScalarAsync();
if (exactResult != "Alice")
{
    throw new InvalidOperationException(
        $"Expected the exact parameter to select Alice; received {exactResult ?? "null"}."
    );
}

Console.WriteLine("Safe SQL witness preserved exact parameter binding.");
