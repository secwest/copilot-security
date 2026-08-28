# Spring Java Collections.addAll command injection

The Spring handler creates an exact mutable `java.util.LinkedList`, passes its
identity to `ProcessBuilder(List)`, and appends the effective command through
`java.util.Collections.addAll`. The positive installs `sh -c <request value>`
before `start()`. Its test runs only a bounded fixed-string `printf` witness.

The matched control preserves the linked-list construction, no-copy builder
binding, static bulk mutation, process dispatch, stream handling, and request
topology, but installs fixed `printf` argv so metacharacters remain data.
