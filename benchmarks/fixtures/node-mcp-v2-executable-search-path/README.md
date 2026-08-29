# MCP v2 executable search-path control

This fixture passes MCP tool input into `options.env.PATH` for a fixed bare `node` command. The harmless witness supplies an empty search path and observes the bounded `ENOENT` lookup failure without executing another program.
