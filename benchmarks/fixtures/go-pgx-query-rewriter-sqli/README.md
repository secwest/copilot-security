# Vulnerable pgx QueryRewriter fixture

The handler puts an HTTP form value in a custom `QueryRewriter`. Its
`RewriteQuery` method formats that field into the first returned value, which
pgx executes as SQL. The deterministic local pgx-compatible witness proves
that an injected predicate exposes an internal record.
