# Repaired Traefik directory/TOML fixture

This source-identical control changes only the proxy image to Traefik 3.7.7.
The split TOML/YAML directory keeps the same public rewrite, authenticated
sibling, shared service, and entry point, but the repaired proxy rejects a
non-normalized replacement before it reaches the inert backend.

`src/witness.mjs` requires an exact official Traefik 3.7.7 binary through
`TRAEFIK_BINARY` and `TRAEFIK_EXPECT=repaired`. It uses only ephemeral loopback
listeners and a new temporary copy of the committed directory, verifies the
direct authentication boundary and repaired rejection, emits bounded JSON,
and removes the temporary state and both processes on exit.
