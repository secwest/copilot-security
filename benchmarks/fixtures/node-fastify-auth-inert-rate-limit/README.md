# Fastify authentication with inert rate-limit configuration

The production source imports Fastify 5, `@fastify/rate-limit`, and bcryptjs,
then registers a literal `/login` route that verifies `request.body.password`.
The route declares a five-attempt `config.rateLimit` object but never registers
the plugin that consumes that configuration. Repeated authentication attempts
therefore continue to reach the password verifier.

`examples/witness.mjs` is an offline, in-memory boundary witness. It sends no
network request, starts no Fastify server, reads no credential, and performs no
real password hashing. It demonstrates only that six attempts reach the
verification boundary when the configuration has no registered consumer.
