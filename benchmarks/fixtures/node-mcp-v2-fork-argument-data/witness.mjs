import assert from "node:assert/strict";
import { runDiagnostic } from "./src/server.mjs";

const option = "--stack-trace-limit=77";
const result = await runDiagnostic(option);
assert.notEqual(result.stackTraceLimit, 77);
assert.deepEqual(result.argv, [option]);
console.log(
  "MCP fork control preserved the inert option-looking value as data.",
);
