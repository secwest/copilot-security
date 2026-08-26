# Vulnerable Traefik directory/TOML fixture

This Traefik 3.7.6 file-directory configuration splits TOML routers, YAML
middlewares, and a TOML backend service across one mounted dynamic directory.
The public `/api` router uses the separator-free `^/api(.*)` to `/$1` rewrite,
while an authenticated sibling protects `/admin` on the same entry point and
backend. A request for `/api../admin` can therefore reach a backend-normalized
`/admin` without executing that sibling router's authentication middleware.

`src/witness.mjs` requires an exact official Traefik 3.7.6 binary through
`TRAEFIK_BINARY` and `TRAEFIK_EXPECT=affected`. It copies the committed split
configuration into a new temporary directory, starts Traefik and an inert
backend on ephemeral `127.0.0.1` listeners, proves the direct route is denied,
and emits bounded JSON evidence. It contacts no external service, uses no real
credential, and removes its temporary directory and both processes on exit.
