import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { runModule } from "./src/server.mjs";

const moduleLookingData = fileURLToPath(
  new URL(
    "../node-mcp-v2-fork-module-path-injection/src/selected-child.mjs",
    import.meta.url,
  ),
);
const result = await runModule(moduleLookingData);
assert.equal(result.selected, "fixed-module");
assert.deepEqual(result.argv, [moduleLookingData]);
console.log(
  "MCP fork control kept a module-looking value in ordinary argument data.",
);
