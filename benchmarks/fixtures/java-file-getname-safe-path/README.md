# Java `File.getName()` safe path fixture

This negative control has the same Spring source, service boundary, `java.io.File.getName()` reduction, and filesystem sink as the vulnerable fixture. It rejects the exact parent component before the sink, so both `..` and nested paths whose basename is `..` fail closed while ordinary document names remain usable.
