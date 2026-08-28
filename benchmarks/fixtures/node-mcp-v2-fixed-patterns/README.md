# MCP v2 fixed-pattern control

This topology-matched control preserves the MCP server, string schema,
`search-diagnostics` tool, same-file `searchLines` helper, diagnostic corpus,
matching operation, and response. Tool input selects only between two
operator-owned regular-expression literals in an immutable local map; it never
becomes regex grammar.

The witness proves both fixed selections still work and that metacharacter and
invalid-pattern strings are rejected as unknown names without dynamic regular
expression construction.
