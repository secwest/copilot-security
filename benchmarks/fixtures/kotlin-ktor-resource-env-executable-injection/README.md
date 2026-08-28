# Ktor typed-resource env executable selection

A Ktor `@Resource` path value occupies the delegated command position of the
POSIX `env` launcher. The native witness substitutes the fixed, harmless
`printf` executable and proves that `env` treats this position as a program
name. It starts one short-lived process and performs no network or file I/O.
