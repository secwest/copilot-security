# Spring Java Collections.addAll argv control

This topology-matched control creates the same exact mutable
`java.util.LinkedList`, passes it without copying to `ProcessBuilder(List)`, and
uses `java.util.Collections.addAll` before the same bounded process dispatch.
It installs `printf`, `%s`, and the request value as separate argv elements, so
shell metacharacters remain ordinary data.
