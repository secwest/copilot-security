import assert from "node:assert/strict";
import { probeSearchPath } from "./src/server.mjs";

const result = await probeSearchPath("");
assert.deepEqual(result, { started: false, code: "ENOENT" });
console.log("MCP PATH witness safely proved tool-controlled command lookup.");
