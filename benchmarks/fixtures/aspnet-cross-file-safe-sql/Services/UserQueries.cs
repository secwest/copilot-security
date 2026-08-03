using System.Data;
using Microsoft.Data.SqlClient;

namespace Secwest.Benchmarks.Services;

public sealed class UserQueries
{
    private readonly string _connectionString;

    public UserQueries(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("App")
            ?? throw new InvalidOperationException("Missing App connection string.");
    }

    public async Task<string?> LookupAsync(string name)
    {
        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand(
            "SELECT DisplayName FROM Users WHERE Name = @name",
            connection
        );
        command.Parameters.Add(
            new SqlParameter("@name", SqlDbType.NVarChar, 128) { Value = name }
        );
        return (string?)await command.ExecuteScalarAsync();
    }
}
