# Spring R2DBC DatabaseClient SQL injection

This executable fixture sends an HTTP-bound username through a controller and
query wrapper into the SQL grammar accepted by Spring `DatabaseClient.sql`.
The returned `FetchSpec` is consumed, so the test demonstrates an unauthorized
row read against an in-memory H2 R2DBC database without network access.

The topology-matched control keeps the SQL fixed and binds the same value as
data. Run `mvn verify` to execute the bounded witness.
