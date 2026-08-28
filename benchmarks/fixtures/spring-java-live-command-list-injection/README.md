# Spring Java live command-list injection

The Spring handler starts with a benign `ProcessBuilder`, obtains the mutable
list returned by `ProcessBuilder.command()`, aliases it, and reconstructs the
effective command as `sh -c <request value>` before `start()`. The test uses
only a bounded fixed-string `printf` witness.

The matched control retains the same getter, alias, list mutations, process
dispatch, stream handling, and request topology but reconstructs fixed
`printf` argv instead of shell grammar.
