# MCP v2 fixed arithmetic parser

This topology-matched control uses the official MCP TypeScript SDK v2 and preserves the expression schema, tool registration, same-file helper, calculation result, and response. Its explicit two-operand `+`/`*` grammar converts matched numeric tokens and never evaluates the tool string as JavaScript source.

Run `npm install` and `npm run witness` with Node.js 22 or later. The witness proves supported arithmetic still works and a fixed object-literal JavaScript expression is rejected.
