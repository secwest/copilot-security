# MCP v2 built-in SQLite parameter binding

This topology-matched control retains the official MCP SDK v2 server, reachable stdio launcher, schema, tool, same-file helper, response, and in-memory `DatabaseSync` instance. Its SQL is fixed and server-owned; tool input reaches only a `StatementSync.run` bound-value argument.

Run `npm install` and `npm run witness` with Node.js 22.13 or later. The same fixed string that changes query structure in the exploit remains one literal database value and produces one row. The witness performs no filesystem, network, subprocess, credential, privilege, or persistent-state operation.
