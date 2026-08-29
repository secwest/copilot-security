import assert from "node:assert/strict";
import action from "./api/controllers/attachments/download-wrapped-thumbnail.js";

const result = await action.fn(
  { filename: "../../private/deployment-secret.txt" },
  { success: (value) => value },
);

assert.equal(result.trim(), "public wrapped thumbnail marker");
assert.doesNotMatch(result, /SAILS_ACTION2_WRAPPER_VICTIM_MARKER/u);
console.log("Sails Action2 relative-wrapper fixed-path control passed.");
