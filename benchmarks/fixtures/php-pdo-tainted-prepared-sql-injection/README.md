# PHP PDO tainted prepared SQL injection

This fixture passes an HTTP query value into the SQL grammar before calling
`PDO::prepare` and then executes that prepared statement. Preparing already
tainted SQL does not separate the input from the command grammar. The scanner
must retain the exact superglobal source, interpolated query, typed PDO
receiver, preparation, and execution boundary before validating database
reachability, privileges, returned data, and concrete impact.

`witness.php` runs the fixture against an in-memory SQLite database. The fixed
injection bytes close the quoted predicate and return both seeded users.
