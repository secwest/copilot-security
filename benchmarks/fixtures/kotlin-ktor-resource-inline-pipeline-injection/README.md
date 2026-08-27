# Ktor typed-resource inline pipeline injection

A Ktor `@Resource` path value reaches the shell-command position of an inline
`ProcessBuilder` inside an exact `startPipeline(listOf(...))` call. The paired
native witness uses only two short-lived processes and proves that fixed shell
grammar interprets a harmless constant command sequence.
