# MCP v2 Function-constructor code injection

This fixture uses the official MCP TypeScript SDK v2 and passes schema-validated tool input through a same-file helper into a global `Function` constructor, retains the compiled function, and explicitly invokes it. The string schema proves only shape and length; it does not constrain the input to arithmetic data.

Run `npm install` and `npm run witness` with Node.js 22 or later. The witness compiles and invokes only fixed side-effect-free arithmetic and object-literal expressions and asserts their inert values. It performs no shell, filesystem, network, credential, persistence, privilege, or destructive operation.
