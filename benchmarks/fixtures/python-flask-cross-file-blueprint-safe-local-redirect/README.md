# Flask cross-file Blueprint local-redirect control

This source-matched Flask 3.1.3 application-factory control mounts the same
sibling Blueprint with the same literal prefix. It percent-encodes the hostile
query value beneath a fixed non-root local destination. The witness inspects
`Location` without following the redirect or performing external I/O.
