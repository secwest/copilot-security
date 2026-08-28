import assert from "node:assert/strict";
import { evaluateExpression } from "./src/server.mjs";

const arithmetic = `
  const { parentPort } = require("node:worker_threads");
  parentPort.postMessage(6 * 7);
`;
const objectAccess = `
  const { parentPort } = require("node:worker_threads");
  parentPort.postMessage(({ answer: 42 }).answer);
`;

assert.equal(await evaluateExpression(arithmetic), 42);
assert.equal(await evaluateExpression(objectAccess), 42);
console.log("MCP worker eval witness returned fixed inert values.");
