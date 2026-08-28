# MCP v2 aliased Node interpreter-option injection

This fixture preserves the official Node executable through one module-scope `runtime = process.execPath` alias. Schema-validated MCP tool input reaches the aliased runtime's option region before any `--`, so the fixed inert `--version` witness is consumed by Node rather than delivered as script data.
