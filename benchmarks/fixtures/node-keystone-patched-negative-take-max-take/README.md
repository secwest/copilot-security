# Patched Keystone negative-take maxTake control

This source-identical control changes only `@keystone-6/core` to 6.5.3. That
release compares the absolute value of `take` with `graphql.maxTake`, so the
same `take: -5` request is rejected before it reaches Prisma.

`witness.mjs` invokes Keystone's public GraphQL context with a bounded in-memory
Prisma test double. It does not open a listener or create a database.
