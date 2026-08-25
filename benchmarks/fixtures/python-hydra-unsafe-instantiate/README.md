# Hydra untrusted target instantiation

This Flask fixture passes a request-controlled configuration object through the
relative `build_component` wrapper to the official
`hydra.utils.instantiate()` API under the exact affected `hydra-core==1.3.3`
release. The caller controls `_target_` and its named arguments.

The witness uses `builtins.eval` only to evaluate the fixed arithmetic expression
`6 * 7`. Returning `42` demonstrates dynamic target lookup and invocation
without invoking a command, touching the filesystem, using the network,
mutating process state, or reading ambient credentials.
