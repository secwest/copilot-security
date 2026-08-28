import assert from "node:assert/strict";
import { recordLookup, recordedTerms, resetAudit } from "./src/server.mjs";

resetAudit();
const fixedInjection = "'); INSERT INTO audit (term) VALUES ('second-row'); --";
assert.equal(recordLookup(fixedInjection), 1);
assert.deepEqual(
  recordedTerms().map(({ term }) => term),
  [fixedInjection],
);
console.log("MCP node:sqlite control bound the fixed value as one SQL value.");
