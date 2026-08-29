# MCP v2 imported Node interpreter-option injection

This fixture obtains the official Node process object through a default `node:process` import and preserves `nodeProcess.execPath` through one module-scope runtime alias. Schema-validated MCP tool input reaches the imported runtime's option region before any `--`, so the fixed inert `--version` witness is consumed by Node rather than delivered as script data.
