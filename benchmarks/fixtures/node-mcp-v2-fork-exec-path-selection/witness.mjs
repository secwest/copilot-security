import assert from "node:assert/strict";
import { runWithExecutable } from "./src/server.mjs";

const result = await runWithExecutable(process.execPath);
assert.equal(result.execPath, process.execPath);
assert.deepEqual(result.argv, []);
console.log("MCP fork witness selected only the current Node executable.");
