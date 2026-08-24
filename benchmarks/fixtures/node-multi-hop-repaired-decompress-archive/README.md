# Repaired decompression archive control

This fixture is source-identical to `node-multi-hop-decompress-archive-escape` and changes only the package identity metadata and `@xhmikosr/decompress` version to 10.2.1. That repair replaces prefix containment with `path.relative`, validates hardlink and symlink targets, guards every file-like write against link pivots, and masks setuid, setgid, and sticky bits.

`npm run witness` submits the same bounded parser result. The repaired package rejects the sibling-prefix destination before creating a file outside the extraction root, and the harness removes its temporary directory.
