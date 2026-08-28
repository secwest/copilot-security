# MCP v2 Node interpreter-option injection

This fixture uses the official MCP TypeScript SDK v2 and passes schema-validated tool input through a same-file helper into a fixed `process.execPath` argument vector without `--`. A dash-prefixed tool value is therefore consumed as a Node runtime option rather than script data.

Run `npm install` and `npm run witness` with Node.js 22 or later. The witness uses only the inert `--version` option and asserts that the runtime consumes it.
