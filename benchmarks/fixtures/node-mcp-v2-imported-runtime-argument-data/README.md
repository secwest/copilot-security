# MCP v2 imported Node interpreter-option control

This topology-matched control keeps the default `node:process` import and the same stable `nodeProcess.execPath` runtime alias, but places an exact `--` before every schema-validated MCP tool value. The fixed marker, `--version`, and `--help` witnesses therefore remain script data instead of entering Node's option grammar.
