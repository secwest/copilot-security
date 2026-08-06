# Java `File.getName()` safe path fixture

This negative control has the same Spring source, service boundary, project-local cross-file `java.io.File.getName()` helper, and filesystem sink as the vulnerable fixture. It rejects the exact returned parent component in the caller before the sink, so both `..` and nested paths whose basename is `..` fail closed while ordinary document names remain usable.
