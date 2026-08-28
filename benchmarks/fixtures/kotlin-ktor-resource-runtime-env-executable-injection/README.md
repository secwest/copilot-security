# Ktor Runtime.exec env executable selection

A Ktor `@Resource` path value occupies the delegated command position of the
POSIX `env` launcher inside the array overload of `java.lang.Runtime.exec`.
The native witness substitutes the fixed, harmless `printf` executable and
proves that this array element selects a program. It starts one short-lived
process and performs no network or file I/O.
