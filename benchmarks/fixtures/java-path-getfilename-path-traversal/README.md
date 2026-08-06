# Java `Path.getFileName()` path traversal fixture

This Spring fixture passes a request parameter through a service into a repository. The repository converts the value with exact `java.nio.file.Path.of` and retains only `Path.getFileName()` before resolving it beneath a document root.

That lexical reduction is not a path-traversal boundary: `Path.of("..").getFileName()` is still the exact `..` name element. A request for `..` therefore selects the parent directory before `content.txt` is read.
