import assert from "node:assert/strict";
import { runCommand } from "./src/server.mjs";

const marker = "MCP_ARGV_DATA_;_NOT_A_COMMAND";
const output = await runCommand(marker);
assert.equal(output, marker);
console.log("MCP v2 argv control preserved the command/data boundary.");
