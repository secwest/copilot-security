# Patched node-tar linkpath control

This source-identical control upgrades only `tar` to 7.5.11. That release strips the drive root before validating the linkpath, so the rewritten parent segments are rejected before a `Link` or `SymbolicLink` entry can be materialized.

`witness.mjs` reproduces the repaired validation order without installing the package.
