import assert from "node:assert/strict";
import { searchLines } from "./src/server.mjs";

assert.deepEqual(searchLines("^error:"), ["error: disk unavailable"]);
assert.deepEqual(searchLines("warning|error"), [
  "error: disk unavailable",
  "warning: cpu elevated",
]);
assert.throws(() => searchLines("["), SyntaxError);

console.log("MCP regex-injection witness passed");
