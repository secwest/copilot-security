# Vulnerable Fastify Static route-guard bypass

The application denies direct access to `/deep/*`, then registers `@fastify/static` 10.1.0 over a root containing the protected files. A request for `/foo/../deep/secret.txt` or its percent-encoded equivalent misses the protected route, matches the static catch-all, and is normalized to the protected file before serving.

`witness.mjs` reproduces the route/normalization disagreement without installing the vulnerable package.
