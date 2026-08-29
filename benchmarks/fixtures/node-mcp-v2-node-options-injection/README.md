# MCP v2 Node process NODE_OPTIONS injection

This fixture passes MCP tool input to a proven Node executable through `spawn(..., { env: { NODE_OPTIONS } })`, allowing one inert checked-in preload to run before a fixed child module.
