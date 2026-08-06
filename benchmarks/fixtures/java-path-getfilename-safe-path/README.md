# Java `Path.getFileName()` safe path fixture

This negative control has the same Spring source, service boundary, project-local cross-file exact `java.nio.file.Path.of`/`Path.getFileName()` helper, and filesystem sink as the vulnerable fixture. It rejects the exact returned parent component in the caller before the sink, so both `..` and nested paths whose last name is `..` fail closed while ordinary document names remain usable.
