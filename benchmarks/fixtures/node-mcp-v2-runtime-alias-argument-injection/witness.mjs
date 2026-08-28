import assert from "node:assert/strict";
import { runCommand } from "./src/server.mjs";

const output = await runCommand("--version");
assert.match(output, /^v\d+\.\d+\.\d+/u);
assert.notEqual(output, "--version");
console.log("MCP aliased-runtime witness consumed one inert Node option.");
