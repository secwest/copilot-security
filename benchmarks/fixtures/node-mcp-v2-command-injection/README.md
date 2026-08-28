# MCP v2 command-injection fixture

The official MCP TypeScript SDK registers a schema-bearing tool whose client-controlled `command` input crosses a same-file helper and reaches `node:child_process.exec`. The bounded witness executes only a fixed Node command that prints an inert marker; it performs no file, network, credential, persistence, or privilege operation.

Run `npm install` and `npm run witness` with Node.js 22 or later.
