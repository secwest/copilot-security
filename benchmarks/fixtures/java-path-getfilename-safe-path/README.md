# Java `Path.getFileName()` safe path fixture

This negative control has the same Spring source, service boundary, exact `java.nio.file.Path.of` construction, `Path.getFileName()` reduction, and filesystem sink as the vulnerable fixture. It rejects the exact reduced parent component before the sink, so both `..` and nested paths whose last name is `..` fail closed while ordinary document names remain usable.
