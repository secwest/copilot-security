using System.Data;

// Hermetic benchmark substitute for the small Microsoft.Data.SqlClient API
// surface used by this fixture. It executes the WHERE expression against
// in-memory rows so the injection has an observable result without NuGet.
// Production code should use the real package.
namespace Microsoft.Data.SqlClient;

public sealed class SqlConnection(string connectionString) : IAsyncDisposable
{
    public string ConnectionString { get; } = connectionString;

    public Task OpenAsync() => Task.CompletedTask;

    internal object? ExecuteScalar(string commandText)
    {
        const string whereMarker = " WHERE ";
        var whereStart = commandText.IndexOf(
            whereMarker,
            StringComparison.OrdinalIgnoreCase
        );
        if (whereStart < 0)
        {
            return null;
        }

        var users = new DataTable();
        users.Columns.Add("Name", typeof(string));
        users.Columns.Add("DisplayName", typeof(string));
        users.Rows.Add("admin", "Administrator");
        users.Rows.Add("alice", "Alice");

        var predicate = commandText[(whereStart + whereMarker.Length)..];
        var matches = users.Select(predicate);
        return matches.Length == 0 ? null : matches[0]["DisplayName"];
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class SqlCommand(string commandText, SqlConnection connection) : IAsyncDisposable
{
    public string CommandText { get; } = commandText;

    public SqlConnection Connection { get; } = connection;

    public Task<object?> ExecuteScalarAsync() =>
        Task.FromResult(Connection.ExecuteScalar(CommandText));

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
