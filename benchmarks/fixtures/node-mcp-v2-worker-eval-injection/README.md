# MCP v2 worker-source code injection

This fixture uses the official MCP TypeScript SDK v2 and passes schema-validated tool input through a same-file helper to `new Worker(expression, { eval: true })`. Node interprets the first constructor argument as JavaScript source in this mode and executes it when the worker comes online. The string schema proves shape and length, not an arithmetic grammar or a code/data boundary.

Run `npm install` and `npm run witness` with Node.js 22 or later. The bounded witness starts workers only with fixed side-effect-free arithmetic and object-access programs, returns the inert value `42` through `parentPort`, and performs no filesystem, network, process, credential, or persistence operation.
