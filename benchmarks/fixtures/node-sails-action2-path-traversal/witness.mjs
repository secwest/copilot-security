import assert from "node:assert/strict";
import action from "./api/controllers/attachments/download-thumbnail.js";

const result = await action.fn(
  { filename: "../../private/deployment-secret.txt" },
  { success: (value) => value },
);

assert.equal(result.trim(), "SAILS_ACTION2_VICTIM_MARKER");
console.log("Sails Action2 traversal witness passed.");
