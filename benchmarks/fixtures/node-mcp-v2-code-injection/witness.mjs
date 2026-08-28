import assert from "node:assert/strict";
import { evaluateExpression } from "./src/server.mjs";

assert.equal(evaluateExpression("6 * 7"), 42);
assert.equal(evaluateExpression("({ answer: 42 }).answer"), 42);
console.log("MCP v2 code-evaluation witness returned fixed inert values.");
