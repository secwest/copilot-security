# Ktor typed-resource inline pipeline argv control

A Ktor `@Resource` path value reaches an inline builder inside an exact
`startPipeline(listOf(...))` call, but the effective program is fixed `printf`
and the value remains a distinct operating-system argument. The paired native
witness proves that shell-looking text remains literal output.
