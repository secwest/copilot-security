# Fastify authentication with an enforced per-route rate limit

This topology-matched control registers `@fastify/rate-limit` with
`global: false` before declaring the same `/login` route, bcryptjs password
verification, and five-attempt `config.rateLimit` object as the vulnerable
fixture. The route-level configuration therefore has an active consumer.

`examples/witness.mjs` is an offline, in-memory boundary witness. It makes no
network request, starts no Fastify server, reads no credential, and performs no
real password hashing. It demonstrates only that the sixth attempt is rejected
before the password-verification boundary when the plugin is registered.
