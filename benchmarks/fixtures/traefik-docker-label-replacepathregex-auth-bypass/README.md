# Vulnerable Traefik Docker-label fixture

This Traefik 3.7.6 Compose project enables the Docker provider through the
canonical local socket and disables implicit container exposure. One explicitly
enabled backend container owns namespaced routing labels: a public
`/cps-benchmark-api` router rewrites `^/cps-benchmark-api(.*)` to the effective
`/$1`, while an authenticated sibling protects `/cps-benchmark-admin` on the
same entry point and backend service.

The project publishes only Traefik's `web` entry point on loopback. The backend
is not host-published and returns only an inert marker when its URL parser
normalizes a request to `/cps-benchmark-admin`. The affected runtime can
forward `/cps-benchmark-api../cps-benchmark-admin` as
`/../cps-benchmark-admin`, reaching that marker without executing the sibling
BasicAuth middleware. The Compose project uses no real credential or external
endpoint and should be run only as an isolated benchmark project.

Run `TRAEFIK_EXPECT=affected node src/witness.mjs` from this directory with an
available Docker Compose engine. The witness chooses a unique project name and
ephemeral loopback port, checks the exact in-container version, proves direct
denial and the crafted backend hit, prints bounded JSON, and always removes its
containers, network, and volumes. Image layers remain in Docker's shared cache.
