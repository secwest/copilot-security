import assert from "node:assert/strict";

const selected = "/attacker.invalid/capture?campaign=fastify-root-prefix";
const location = "/" + selected;
const resolved = new URL(location, "https://scanner.invalid/start");

assert.equal(
  location,
  "//attacker.invalid/capture?campaign=fastify-root-prefix",
);
assert.equal(resolved.origin, "https://attacker.invalid");
console.log({ control: false, attacker_origin_selected: 1 });
