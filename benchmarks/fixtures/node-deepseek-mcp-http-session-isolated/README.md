# DeepSeek MCP HTTP session isolation

This source-identical control changes only the production package to
`@arikusi/deepseek-mcp-server` 1.7.0. The repaired HTTP factory constructs one
`SessionStore` per MCP session, so a caller-selected `session_id` colliding with
another client cannot enumerate or retrieve that client's conversation.

The bounded witness creates two real packaged stores, reuses the same inert key,
proves that the attacker-side store remains empty, and clears both stores.
