# DeepSeek MCP HTTP cross-session authorization bypass

The production launcher selects Streamable HTTP before dynamically loading
`@arikusi/deepseek-mcp-server` 1.6.0. That release gives each HTTP connection a
separate MCP server but routes every tool handler to one process-global
`SessionStore`, keyed by caller-provided `session_id` values.

The bounded witness opens no listener and makes no API request. It simulates two
HTTP-client flows against the real packaged store, writes one inert victim
message, proves that the second flow receives the same singleton and can read
the marker, and clears all state in `finally`.
