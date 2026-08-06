# Spring multi-hop safe path access

The request crosses the same controller, `DocumentFacade`, `DocumentService`,
and `DocumentStore` topology as the vulnerable fixture. The storage boundary
rejects absolute input, normalizes the candidate, uses component-aware
`Path.startsWith`, follows the existing target with `toRealPath`, and checks
the real target against the real server-owned root before reading it. The root
must not be attacker-writable; stronger directory-handle APIs are still
required where concurrent rename races are in scope.
