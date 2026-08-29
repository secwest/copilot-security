import assert from "node:assert/strict";
import { runWithExecutable } from "./src/server.mjs";

const executableLookingData = process.execPath;
const result = await runWithExecutable(executableLookingData);
assert.equal(result.execPath, process.execPath);
assert.deepEqual(result.argv, [executableLookingData]);
console.log(
  "MCP fork control kept an executable-looking value in ordinary argument data.",
);
