# Reachable Keystone negative-take maxTake bypass

This fixture exports a Keystone configuration whose queryable `Post` list sets
`graphql.maxTake` to 3 while pinning `@keystone-6/core` 6.5.2. In that release,
a GraphQL request with `take: -5` bypasses the positive-only comparison and
reaches the Prisma boundary with five requested rows.

`witness.mjs` invokes Keystone's public GraphQL context with a bounded in-memory
Prisma test double. It does not open a listener or create a database. The test
double records the exact argument passed by Keystone's real resolver, allowing
the same script to distinguish the vulnerable and fixed package behavior.
