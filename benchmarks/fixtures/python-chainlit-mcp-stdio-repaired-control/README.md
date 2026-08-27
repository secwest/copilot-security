# Chainlit MCP stdio client-command boundary

This paired fixture models an official Chainlit application with MCP and legacy
stdio enabled. The affected case pins Chainlit 2.11.1; the repaired control pins
2.12.0 and is otherwise source-identical.

The witness is deliberately non-executing. On 2.11.1 it invokes only the pure
command validator with fixed inert text and records the parsed executable and
arguments. It never passes those values to a subprocess, shell, stdio client,
filesystem operation, network client, or credential-bearing API. On 2.12.0 it
proves the validator is absent and the client request schema rejects legacy
`stdio`/`fullCommand` input.
