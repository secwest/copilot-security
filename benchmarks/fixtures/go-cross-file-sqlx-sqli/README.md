# Go cross-file sqlx SQL injection fixture

The HTTP query value crosses one same-package function boundary, is formatted into SQL query text, and reaches the destination-before-query `sqlx.DB.Select` boundary. The executable witness uses a deterministic local, API-compatible sqlx adapter over `database/sql` to prove that an injected predicate exposes an otherwise internal record without downloading dependencies.
