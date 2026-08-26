# Repaired Traefik ReplacePathRegex fixture

This source-identical control changes only the Compose image from Traefik
3.7.6 to 3.7.7. The repaired middleware rejects a replacement path whose
normalized form differs, so `/api../admin` does not reach the backend while a
direct `/admin` request remains protected by authentication.

`src/witness.mjs` requires an exact official Traefik 3.7.7 binary through
`TRAEFIK_BINARY` and `TRAEFIK_EXPECT=repaired`. It starts both Traefik and an
inert backend on ephemeral `127.0.0.1` listeners, proves the direct route is
denied, and prints only bounded JSON evidence that the crafted path was
rejected before reaching the backend. It contacts no external service, uses no
real credential, writes only inside a new temporary directory, and removes
that directory and both processes on exit.
