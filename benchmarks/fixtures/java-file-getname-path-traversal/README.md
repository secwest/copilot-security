# Java `File.getName()` path traversal fixture

This Spring fixture passes a request parameter through a service into a repository. The repository calls a package-access static helper in a separate compilation unit that reduces the value with `java.io.File.getName()` before resolving the returned name beneath a document root.

That reduction is not a path-traversal boundary: `new File("..").getName()` is still `".."`. A request for `..` therefore selects the parent directory before `content.txt` is read.
