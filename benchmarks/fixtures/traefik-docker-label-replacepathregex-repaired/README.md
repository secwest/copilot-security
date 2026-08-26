# Repaired Traefik Docker-label fixture

This source-identical control changes only the proxy image from Traefik 3.7.6
to 3.7.7. The Docker-provider labels still define the same public rewrite,
authenticated sibling route, loopback-published entry point, backend service,
and inert marker.

Traefik 3.7.7 rejects the non-normalized replacement before proxying, so
`/cps-benchmark-api../cps-benchmark-admin` cannot reach the backend marker while
a direct `/cps-benchmark-admin` request remains behind BasicAuth. The backend is
not host-published, the project uses no real credential or external endpoint,
and it should be run only as an isolated benchmark project.

Run `TRAEFIK_EXPECT=repaired node src/witness.mjs` from this directory with an
available Docker Compose engine. The source-identical witness chooses a unique
project name and ephemeral loopback port, checks the exact in-container
version, proves direct denial and rejection before the crafted backend hit,
prints bounded JSON, and always removes its containers, network, and volumes.
Image layers remain in Docker's shared cache.
