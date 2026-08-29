import assert from "node:assert/strict";
import { runCommand } from "./src/server.mjs";

assert.equal(
  await runCommand("MCP_IMPORTED_RUNTIME_DATA_OK"),
  "MCP_IMPORTED_RUNTIME_DATA_OK",
);
assert.equal(await runCommand("--version"), "--version");
assert.equal(await runCommand("--help"), "--help");
console.log("MCP imported-runtime control preserved all fixed input as data.");
