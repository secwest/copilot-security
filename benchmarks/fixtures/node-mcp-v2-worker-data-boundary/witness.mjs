import assert from "node:assert/strict";
import { evaluateExpression } from "./src/server.mjs";

assert.equal(await evaluateExpression("6 * 7"), 42);
assert.equal(await evaluateExpression("40 + 2"), 42);
assert.throws(
  () => evaluateExpression("({ answer: 42 }).answer"),
  /Unsupported arithmetic expression/u,
);
console.log("MCP workerData control kept fixed worker source and returned 42.");
