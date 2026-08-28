# MCP v2 fixed-grammar Function control

This topology-matched control uses the official MCP TypeScript SDK v2 and preserves the expression schema, tool registration, same-file helper, compiled `Function` invocation, calculation result, and response. The tool string first passes an explicit two-operand `+`/`*` grammar; only converted numbers and an allowlisted operator reach the compiled function as data, while the function source is a fixed operator-owned literal.

Run `npm install` and `npm run witness` with Node.js 22 or later. The witness proves supported arithmetic still works and a fixed object-literal JavaScript expression is rejected.
