import assert from "node:assert/strict";
import { evaluateExpression } from "./src/server.mjs";

assert.equal(evaluateExpression("6 * 7"), 42);
assert.equal(evaluateExpression("9 + 4"), 13);
assert.throws(
  () => evaluateExpression("({ answer: 42 }).answer"),
  /Unsupported arithmetic expression/u,
);
console.log(
  "MCP v2 fixed-grammar Function control kept tool input in the data role.",
);
