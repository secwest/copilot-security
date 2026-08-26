# Vulnerable Traefik ReplacePathRegex fixture

This Traefik 3.7.6 file-provider configuration exposes `/api` through the
separator-free `^/api(.*)` to `/$1` rewrite while an authenticated sibling
router protects `/admin` on the same entry point and backend. A request for
`/api../admin` can therefore become `/../admin` after routing and reach a
backend-normalized `/admin` without executing the authentication middleware.

`src/witness.mjs` requires an exact official Traefik 3.7.6 binary through
`TRAEFIK_BINARY` and `TRAEFIK_EXPECT=affected`. It starts both Traefik and an
inert backend on ephemeral `127.0.0.1` listeners, proves the direct route is
denied, and prints only bounded JSON evidence that the crafted path reached the
marker. It contacts no external service, uses no real credential, writes only
inside a new temporary directory, and removes that directory and both
processes on exit.
