# R2DBC SPI statement SQL injection

This executable Java fixture demonstrates request-controlled SQL grammar crossing the official `io.r2dbc.spi.Connection.createStatement(String)` boundary and reaching `Statement.execute()`.

The JUnit witness uses a private in-memory H2 database. The payload changes only fixture-local query semantics and proves an unauthorized read of the seeded administrator row. It performs no network access and touches no external database.

Run it with:

```sh
mvn --batch-mode --no-transfer-progress verify
```
