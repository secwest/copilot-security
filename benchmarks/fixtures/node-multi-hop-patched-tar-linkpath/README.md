# Patched node-tar linkpath control

This source-identical control upgrades `tar` to 7.5.21. The linkpath repair first
shipped in 7.5.11 strips the drive root before validation, so rewritten parent
segments are rejected before a `Link` or `SymbolicLink` entry can be
materialized. The later pin also closes the decompression-ratio and
member-selection recursion advisories, keeping this canonical negative control
free of unrelated reachable node-tar defects.

`witness.mjs` reproduces the repaired validation order without installing the package.
