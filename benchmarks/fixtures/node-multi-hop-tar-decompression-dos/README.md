# Reachable node-tar decompression amplification

This fixture models an upload path that sends an attacker-controlled compressed
archive through three application wrappers to `tar.list`. It pins `tar` 7.5.18,
the last release before the default cumulative decompression-ratio guard added
for [GHSA-23hp-3jrh-7fpw / CVE-2026-59873](https://github.com/advisories/GHSA-23hp-3jrh-7fpw).

`witness.mjs` creates a bounded in-memory tar containing 8 MiB of zeros, writes
its small gzip form to a private temporary directory, and records whether the
installed parser aborts on the expansion ratio. It never extracts the payload.
