import assert from "node:assert/strict";
import { searchLines } from "./src/server.mjs";

assert.deepEqual(searchLines("errors"), ["error: disk unavailable"]);
assert.deepEqual(searchLines("warnings"), ["warning: cpu elevated"]);
assert.deepEqual(searchLines("^error:"), []);
assert.deepEqual(searchLines("["), []);

console.log("MCP fixed-pattern witness passed");
