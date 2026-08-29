import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { runModule } from "./src/server.mjs";

const fixtureModule = fileURLToPath(
  new URL("./src/selected-child.mjs", import.meta.url),
);
const result = await runModule(fixtureModule);
assert.equal(result.selected, "fixture-local-selected-module");
assert.deepEqual(result.argv, []);
console.log("MCP fork witness selected one checked-in inert child module.");
