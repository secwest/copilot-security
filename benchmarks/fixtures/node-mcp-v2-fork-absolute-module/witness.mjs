import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { runFromDirectory } from "./src/server.mjs";

const alternateDirectory = fileURLToPath(
  new URL("./alternate/", import.meta.url),
);
const result = await runFromDirectory(alternateDirectory);
assert.deepEqual(result, { selected: "fixed-absolute-child" });
console.log("MCP fork control kept the absolute child fixed across cwd input.");
