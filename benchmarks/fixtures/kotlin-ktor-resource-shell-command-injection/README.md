# Ktor typed-resource command replacement injection

A Ktor `@Resource` path value reaches the command-string position installed by
`ProcessBuilder.command("sh", "-c", commandLine)`. The initial fixed command is
replaced before `start()`, so the resource value participates in shell grammar.
The paired native witness expands only a fixed inert environment marker.
