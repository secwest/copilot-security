# Nx self-hosted HTTP cache archive containment

This source-identical control changes only Nx to 22.7.7. Its
containment-checked extractor rejects or contains the same parent traversal tar
entry, so the inert sentinel is not written outside the per-hash cache
directory.

`witness.test.mjs` uses the real installed package, an ephemeral loopback-only
server, and a fresh disposable root. Its archive contains no executable data and
writes only an inert sentinel within that root. The witness removes the root and
closes the server in `finally`.
