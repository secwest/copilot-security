import assert from "node:assert/strict";
import { runWithEnvironmentData } from "./src/server.mjs";

const result = await runWithEnvironmentData("--require=./src/preload.cjs");
assert.deepEqual(result, { preload: null });
console.log("MCP process control kept NODE_OPTIONS-looking text as inert data.");
