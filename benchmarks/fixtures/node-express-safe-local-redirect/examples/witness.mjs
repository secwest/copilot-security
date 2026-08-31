import assert from "node:assert/strict";

const selected = "/attacker.invalid/capture?campaign=express-local-prefix";
const location = "/continue/" + encodeURIComponent(selected);
const resolved = new URL(location, "https://scanner.invalid/start");

assert.equal(resolved.origin, "https://scanner.invalid");
assert.equal(
  resolved.pathname,
  "/continue/%2Fattacker.invalid%2Fcapture%3Fcampaign%3Dexpress-local-prefix",
);
console.log({ control: true, attacker_origin_selected: 0 });
