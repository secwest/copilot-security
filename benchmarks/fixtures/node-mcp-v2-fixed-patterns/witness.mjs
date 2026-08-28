import assert from "node:assert/strict";
import { searchText } from "./src/server.mjs";

assert.equal(searchText("errors", "error: disk unavailable"), true);
assert.equal(searchText("warnings", "warning: cpu elevated"), true);
assert.equal(searchText("errors", "ok"), false);
assert.equal(searchText("^error:", "error: disk unavailable"), false);
assert.equal(searchText("[", "fixed short text"), false);

console.log("MCP fixed-pattern witness passed");
