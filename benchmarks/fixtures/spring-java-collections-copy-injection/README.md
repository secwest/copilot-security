# Spring Java Collections.copy command injection

The Spring handler binds a caller-owned mutable command list to
`ProcessBuilder(List)`, then uses exact `java.util.Collections.copy` semantics
to replace its three-element prefix. The positive copies `sh`, `-c`, and the
request value into the retained list before `start()`. Its test executes only a
bounded fixed-string `printf` witness.

The matched control preserves construction, no-copy builder binding, static
copy, process dispatch, timeout, stdout, and request topology, but copies fixed
`printf` argv so shell metacharacters remain data.
