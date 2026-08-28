import assert from "node:assert/strict";
import { runCommand } from "./src/server.mjs";

assert.equal(await runCommand("MCP_ARGUMENT_DATA_OK"), "MCP_ARGUMENT_DATA_OK");
assert.equal(await runCommand("--version"), "--version");
assert.equal(await runCommand("--help"), "--help");
console.log("MCP v2 end-of-options control preserved all tool input as data.");
