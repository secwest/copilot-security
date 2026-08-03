# ASP.NET cross-file SQL injection

The controller passes a query parameter through a constructor-injected service
into the SQL text argument of `SqlCommand`.

`Compatibility/SqlClient.cs` supplies the API surface needed to compile the
fixture without network package restoration and executes the constructed
`WHERE` expression against in-memory user rows. A quote-and-`OR` payload can
therefore select a different user; the application path keeps the production
`Microsoft.Data.SqlClient` namespace and call shape.
