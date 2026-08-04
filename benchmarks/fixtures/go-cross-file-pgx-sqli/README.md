# Go pgx SQL-injection witness

An indexed HTTP query value crosses one same-package function boundary, is formatted into the SQL-text argument of `pgxpool.Pool.Query`, and changes the deterministic query result. The local module replacement implements only the documented pgx v5 query signature so the witness remains offline and reproducible; the scanner still requires the exact public pgx v5 import path and receiver type.
