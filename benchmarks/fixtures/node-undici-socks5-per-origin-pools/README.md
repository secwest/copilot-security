# Undici SOCKS5 per-origin pools

This source-identical control changes only Undici to 7.28.0. The repaired agent
keys pools by origin, so the later credentialed billing request reaches its
intended second origin rather than the request-controlled first origin.

`witness.mjs` runs the same bounded differential through two ephemeral
loopback HTTP origins and one loopback-only SOCKS5 proxy. It uses an inert
authorization marker, contacts no external endpoint, and closes every resource.
