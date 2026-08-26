# Repaired Traefik Docker-label fixture

This source-identical control changes only the proxy image from Traefik 3.7.6
to 3.7.7. The Docker-provider labels still define the same public rewrite,
authenticated sibling route, loopback-published entry point, backend service,
and inert marker.

Traefik 3.7.7 rejects the non-normalized replacement before proxying, so
`/api../admin` cannot reach the backend marker while a direct `/admin` request
remains behind BasicAuth. The backend is not host-published, the project uses
no real credential or external endpoint, and it should be run only as an
isolated benchmark project.
