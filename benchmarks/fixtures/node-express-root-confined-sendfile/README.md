# Root-confined Express `sendFile`

This topology-matched control passes the same remote query field to the same
literal Express route and `response.sendFile` sink, but supplies a fixed
operator-owned absolute `root`. Express validates that the requested path
resolves within that root.

The witness uses only disposable inert marker files and an in-memory HTTP
request/response pair. It starts no listener and performs no network access.
