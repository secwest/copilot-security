# MCP v2 prepared SQLite SQL injection

This fixture uses the official MCP TypeScript SDK v2 and passes schema-validated tool input through the `lookupRole` same-file helper into argument zero of `DatabaseSync.prepare`. The returned official `StatementSync` is then executed with `get()`. Interpolation changes SQL grammar before preparation; the string schema proves only shape and length.

Run `npm install` and `npm run witness` with Node.js 22.13 or later. The bounded witness uses only an in-memory database and a fixed inert value that exposes one seeded internal role. It does not touch the filesystem, network, subprocesses, credentials, privileges, or persistent state.
