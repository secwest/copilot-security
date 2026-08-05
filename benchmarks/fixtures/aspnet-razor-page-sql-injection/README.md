# Razor Page handler SQL injection fixture

This executable ASP.NET Core Razor Pages fixture passes the unannotated
`filter` parameter of the named `OnGetLookupAsync` handler through a typed,
constructor-injected `UserQueries` service and concatenates it into a
`SqlCommand` query. Razor Pages model binding makes the handler parameter a
remote source without a controller-style `[FromQuery]` annotation.

The compatibility SQL client keeps the benchmark hermetic and turns the
injected predicate into an observable unauthorized `Administrator` result.
