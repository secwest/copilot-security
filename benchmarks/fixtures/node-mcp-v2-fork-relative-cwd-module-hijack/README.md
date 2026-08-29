# MCP v2 fork relative-cwd module selection

This fixture passes MCP tool input to `child_process.fork` as `cwd` while a fixed relative `modulePath` is resolved from that externally selected directory.
