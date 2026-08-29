# R2DBC SPI bound-statement control

This topology-matched control keeps the statement text fixed and passes the
same injection-shaped request value only through `Statement.bind`. The JUnit
witness fully consumes the result from a private in-memory H2 database and
proves that no row is returned.
