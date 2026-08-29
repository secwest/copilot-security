import assert from "node:assert/strict";
import { probeFixedSearchPath } from "./src/server.mjs";

const result = await probeFixedSearchPath("");
assert.equal(result.started, true);
assert.match(result.version, /^v\d+\./u);
console.log("MCP PATH control launched only the fixed current Node executable.");
