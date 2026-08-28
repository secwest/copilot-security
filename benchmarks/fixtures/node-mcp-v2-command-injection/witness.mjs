import assert from "node:assert/strict";
import { runCommand } from "./src/server.mjs";

const executable = `"${process.execPath.replaceAll('"', '\\"')}"`;
const output = await runCommand(
  `${executable} -e "process.stdout.write('MCP_COMMAND_WITNESS_OK')"`,
);
assert.equal(output, "MCP_COMMAND_WITNESS_OK");
console.log("MCP v2 command witness passed with bounded inert output.");
