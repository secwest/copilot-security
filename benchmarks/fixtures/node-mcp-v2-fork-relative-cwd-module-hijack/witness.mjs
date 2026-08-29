import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { runFromDirectory } from "./src/server.mjs";

const controlledDirectory = fileURLToPath(
  new URL("./controlled/", import.meta.url),
);
const result = await runFromDirectory(controlledDirectory);
assert.deepEqual(result, { selected: "controlled-relative-child" });
console.log(
  "MCP fork witness resolved a fixed relative child from the selected cwd.",
);
