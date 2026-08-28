import assert from "node:assert/strict";
import { searchText } from "./src/server.mjs";

assert.equal(searchText("^error:", "error: disk unavailable"), true);
assert.equal(searchText("warning|error", "warning: cpu elevated"), true);
assert.equal(searchText("^error:", "ok"), false);
assert.throws(() => searchText("[", "fixed short text"), SyntaxError);

console.log("MCP regex-injection witness passed");
