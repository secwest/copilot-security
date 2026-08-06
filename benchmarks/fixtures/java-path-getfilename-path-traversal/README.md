# Java `Path.getFileName()` path traversal fixture

This Spring fixture passes a request parameter through a service into a repository. The repository converts the value with exact `java.nio.file.Path.of` and retains only `Path.getFileName()` before resolving it beneath a document root.

That lexical reduction is not a path-traversal boundary: `Path.of("..").getFileName()` is still the exact `..` name element. The repository notices and logs that exact parent component but does not terminate that branch. A later null-state exception is unrelated to the attacker-controlled value. A request for `..` therefore still selects the parent directory before `content.txt` is read. This deliberately adversarial shape proves that a scanner does not credit a decorative check merely because another nearby branch throws.
