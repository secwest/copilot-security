# ASP.NET cross-file safe SQL

The controller passes the same request value through the same service boundary,
but the service keeps SQL text fixed and binds the value with a typed parameter.

`Compatibility/SqlClient.cs` supplies the API surface needed to compile the
fixture without network package restoration and performs an exact lookup from
the typed `@name` parameter. The application path keeps the production
`Microsoft.Data.SqlClient` namespace and call shape.
