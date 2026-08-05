using System.Data;

// Hermetic benchmark substitute for the small Microsoft.Data.SqlClient API
// surface used by this fixture. It performs an exact value lookup so the
// parameterized control remains functional without NuGet. Production code
// should use the real package.
namespace Microsoft.Data.SqlClient;

public sealed class SqlConnection(string connectionString) : IAsyncDisposable
{
    public string ConnectionString { get; } = connectionString;

    public Task OpenAsync() => Task.CompletedTask;

    internal object? LookupExact(object? value) =>
        value is string name && name.Equals("alice", StringComparison.Ordinal)
            ? "Alice"
            : null;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class SqlCommand(string commandText, SqlConnection connection) : IAsyncDisposable
{
    public string CommandText { get; } = commandText;

    public SqlConnection Connection { get; } = connection;

    public SqlParameterCollection Parameters { get; } = new();

    public Task<object?> ExecuteScalarAsync() =>
        Task.FromResult(Connection.LookupExact(Parameters.Value("@filter")));

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class SqlParameter(string parameterName, SqlDbType sqlDbType, int size)
{
    public string ParameterName { get; } = parameterName;

    public SqlDbType SqlDbType { get; } = sqlDbType;

    public int Size { get; } = size;

    public object? Value { get; set; }
}

public sealed class SqlParameterCollection
{
    private readonly List<SqlParameter> _parameters = [];

    public void Add(SqlParameter parameter) => _parameters.Add(parameter);

    internal object? Value(string parameterName) =>
        _parameters.Find((parameter) => parameter.ParameterName == parameterName)?.Value;
}
