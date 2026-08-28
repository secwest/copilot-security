# MCP v2 regular-expression injection

The `search-diagnostics` MCP tool accepts a string schema and passes the tool's
`pattern` property through the same-file `searchLines` helper into JavaScript's
global `RegExp` constructor. The resulting expression is executed with
`RegExp.prototype.test`, so regex metacharacters control matching grammar and
an invalid character class throws synchronously.

The witness uses only short fixed strings. It demonstrates metacharacter and
syntax control without evaluating a catastrophic-backtracking expression or
performing any shell, filesystem, network, credential, persistence, privilege,
or destructive operation.
