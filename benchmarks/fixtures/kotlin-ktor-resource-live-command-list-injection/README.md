# Ktor typed-resource live command-list injection

A Ktor `@Resource` path value reaches the shell-command position through the
mutable list returned by `ProcessBuilder.command()`. The constructor retains the
original list, the getter returns the builder's live list, and a builder alias
starts the mutated command. The paired native witness expands only a fixed inert
environment marker.
