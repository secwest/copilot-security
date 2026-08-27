# PHP PDO parameterized query control

This topology-identical control keeps the HTTP source, typed PDO receiver,
preparation, execution, and result path, but the SQL template contains a
placeholder and supplies the untrusted value only as execute-time parameter
data. The scanner must not treat parameter data as SQL command grammar.

`witness.php` supplies the same bytes to the same in-memory SQLite data set and
requires zero rows, proving that the placeholder preserves the data boundary.
