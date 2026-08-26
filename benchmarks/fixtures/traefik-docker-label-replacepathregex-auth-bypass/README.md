# Vulnerable Traefik Docker-label fixture

This Traefik 3.7.6 Compose project enables the Docker provider through the
canonical local socket and disables implicit container exposure. One explicitly
enabled backend container owns all routing labels: a public `/api` router
rewrites `^/api(.*)` to the effective `/$1`, while an authenticated sibling
protects `/admin` on the same entry point and backend service.

The project publishes only Traefik's `web` entry point on loopback. The backend
is not host-published and returns only an inert marker when its URL parser
normalizes a request to `/admin`. The affected runtime can forward
`/api../admin` as `/../admin`, reaching that marker without executing the
sibling BasicAuth middleware. The Compose project uses no real credential or
external endpoint and should be run only as an isolated benchmark project.
