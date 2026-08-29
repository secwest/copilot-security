import assert from "node:assert/strict";
import { runDiagnostic } from "./src/server.mjs";

const result = await runDiagnostic("--stack-trace-limit=77");
assert.equal(result.stackTraceLimit, 77);
assert.deepEqual(result.argv, []);
console.log("MCP fork witness consumed one inert execArgv option.");
