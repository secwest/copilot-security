import assert from "node:assert/strict";
import { recordLookup, recordedTerms, resetAudit } from "./src/server.mjs";

resetAudit();
assert.equal(recordLookup("ordinary"), 1);
assert.deepEqual(
  recordedTerms().map(({ term }) => term),
  ["ordinary"],
);

resetAudit();
const fixedInjection = "'); INSERT INTO audit (term) VALUES ('second-row'); --";
assert.equal(recordLookup(fixedInjection), 2);
assert.deepEqual(
  recordedTerms().map(({ term }) => term),
  ["", "second-row"],
);
console.log("MCP node:sqlite witness changed SQL structure with a fixed value.");
