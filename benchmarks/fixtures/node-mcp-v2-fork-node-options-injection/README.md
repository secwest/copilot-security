# MCP v2 fork NODE_OPTIONS injection

This fixture passes MCP tool input to the forked Node runtime through `options.env.NODE_OPTIONS`, allowing an inert checked-in preload to run before the fixed child module.
