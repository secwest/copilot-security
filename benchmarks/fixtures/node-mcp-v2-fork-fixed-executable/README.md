# MCP v2 fixed fork executable

This control fixes `child_process.fork`'s executable to `process.execPath` and passes the same executable-looking MCP tool value only in ordinary child argument data.
