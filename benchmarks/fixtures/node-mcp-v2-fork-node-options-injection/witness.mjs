import assert from "node:assert/strict";
import { runWithNodeOptions } from "./src/server.mjs";

const result = await runWithNodeOptions("--require=./src/preload.cjs");
assert.deepEqual(result, { preload: "checked-in-preload" });
console.log(
  "MCP fork witness loaded only the checked-in inert NODE_OPTIONS preload.",
);
