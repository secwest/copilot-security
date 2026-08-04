# Vulnerable pgconn SQL fixture

This offline Go module replaces the exact pgx v5 module path with a deterministic, signature-compatible `pgconn` witness. Request data is formatted into SQL passed to simple-protocol `PgConn.Exec`; the preview test proves an injected predicate exposes an internal record without requiring PostgreSQL or dependency downloads.
