# MCP v2 prepared SQLite parameter binding

This topology-matched control retains the official MCP SDK v2 server, reachable stdio launcher, schema, tool, same-file helper, response, in-memory `DatabaseSync`, `prepare`, and `StatementSync.get` execution. Its SQL is fixed and server-owned; tool input reaches only the bound-value argument of `get()`.

Run `npm install` and `npm run witness` with Node.js 22.13 or later. The same fixed string that changes SQL grammar in the exploit remains one literal database value and cannot expose the seeded internal role. The witness performs no filesystem, network, subprocess, credential, privilege, or persistent-state operation.
