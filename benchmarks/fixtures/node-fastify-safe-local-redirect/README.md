# Fastify fixed-local redirect control

This topology-matched control uses the same Fastify 5 route, query source, and
redirect sink. It percent-encodes the remote value beneath the fixed non-root
`/continue/` path, so the Location cannot select another authority.

Run `npm run witness` to check URL resolution without starting a server or
making a network request. The witness uses only fixed synthetic values.
