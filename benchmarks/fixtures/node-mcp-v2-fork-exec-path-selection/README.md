# MCP v2 fork execPath selection

This fixture places schema-validated MCP tool input in `child_process.fork`'s `options.execPath`. The bounded witness supplies only the current Node executable and observes the child through private IPC.
