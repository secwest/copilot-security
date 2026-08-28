# MCP v2 built-in SQLite SQL injection

This fixture uses the official MCP TypeScript SDK v2 and passes schema-validated tool input through the `recordLookup` same-file helper into argument zero of `DatabaseSync.exec`. The helper interpolates the value into SQL text, so the string schema proves only shape and length—not SQL grammar or a query/data boundary.

Run `npm install` and `npm run witness` with Node.js 22.13 or later. The bounded witness uses only an in-memory database. A fixed value adds a second inert audit row, demonstrating that input changed statement structure without touching the filesystem, network, subprocesses, credentials, privileges, or persistent state.
