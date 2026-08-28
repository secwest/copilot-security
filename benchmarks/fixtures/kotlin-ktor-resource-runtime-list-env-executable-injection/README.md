# Ktor Runtime.exec list-conversion env executable selection

A Ktor `@Resource` path value occupies the delegated command position of the
POSIX `env` launcher after an exact Kotlin collection-to-array conversion for
the array overload of `java.lang.Runtime.exec`. The native witness substitutes
the fixed, harmless `printf` executable and proves that the converted element
selects a program. It starts one short-lived process and performs no network or
file I/O.
