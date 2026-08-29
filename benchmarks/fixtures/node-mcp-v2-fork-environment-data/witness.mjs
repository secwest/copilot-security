import assert from "node:assert/strict";
import { runWithEnvironmentData } from "./src/server.mjs";

const optionLookingData = "--require=./src/preload.cjs";
const result = await runWithEnvironmentData(optionLookingData);
assert.deepEqual(result, { preload: null, data: optionLookingData });
console.log(
  "MCP fork control kept option-looking text as ordinary environment data.",
);
