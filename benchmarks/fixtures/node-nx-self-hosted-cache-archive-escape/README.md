# Nx self-hosted HTTP cache archive escape

This fixture models a cache-consuming Nx CI task with a nonempty
`NX_SELF_HOSTED_REMOTE_CACHE_SERVER`. Nx 22.7.6 extracts a returned gzip tar
without containing parent traversal entries to the per-hash cache directory.

`witness.test.mjs` uses the real installed package, an ephemeral loopback-only
server, and a fresh disposable root. Its archive contains no executable data and
writes only an inert sentinel within that root. The witness removes the root and
closes the server in `finally`.
