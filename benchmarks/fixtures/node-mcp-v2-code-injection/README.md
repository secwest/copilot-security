# MCP v2 JavaScript code injection

This fixture uses the official MCP TypeScript SDK v2 and passes schema-validated tool input through a same-file helper to direct JavaScript `eval`. The string schema proves only shape and length; it does not constrain the input to an arithmetic grammar.

Run `npm install` and `npm run witness` with Node.js 22 or later. The witness evaluates only fixed side-effect-free arithmetic and object-literal expressions and asserts their inert values.
