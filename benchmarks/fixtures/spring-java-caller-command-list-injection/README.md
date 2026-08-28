# Spring Java caller-owned command-list injection

The Spring handler creates a mutable caller-owned `ArrayList`, passes that exact
list to `ProcessBuilder(List)`, and mutates it through another caller alias after
binding. Because the JDK does not copy this list, the effective command becomes
`sh -c <request value>` before `start()`. The test uses only a bounded
fixed-string `printf` witness.

The matched control retains the same list construction, no-copy builder
binding, alias, mutations, process dispatch, stream handling, and request
topology, but reconstructs fixed `printf` argv instead of shell grammar.
