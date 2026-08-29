# MCP v2 fork execArgv injection

This fixture keeps the forked module fixed but places schema-validated MCP tool input in `child_process.fork`'s `execArgv` option. The bounded inert `--stack-trace-limit=77` witness changes only the child Node runtime's observable stack-trace limit.
