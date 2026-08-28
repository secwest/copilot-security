# Ktor Runtime.exec env argv control

This paired control retains the same Ktor source, `Runtime.exec` array overload,
POSIX `env` launcher, process execution, output handling, and response path. A
fixed `printf` executable precedes the request value, so `env` passes that value
only as ordinary argument data. The native witness starts one short-lived
process and performs no network or file I/O.
