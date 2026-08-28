import assert from "node:assert/strict";
import { lookupRole } from "./src/server.mjs";

assert.equal(lookupRole("public"), "viewer");
const fixedInjection = "missing' OR role = 'admin' --";
assert.equal(lookupRole(fixedInjection), "admin");
console.log(
  "MCP node:sqlite prepared-SQL witness exposed one fixed internal role.",
);
