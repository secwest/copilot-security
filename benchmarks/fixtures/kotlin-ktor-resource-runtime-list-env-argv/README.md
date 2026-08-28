# Ktor Runtime.exec list-conversion env argv control

This paired control retains the same Ktor source, Kotlin collection-to-array
conversion, `Runtime.exec` array overload, POSIX `env` launcher, process
execution, output handling, and response path. A fixed `printf` executable
precedes the request value, so `env` passes that value only as ordinary argument
data. The native witness starts one short-lived process and performs no network
or file I/O.
