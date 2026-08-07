import assert from "node:assert/strict";

function patchedMerge(target, source) {
  const result = {};
  for (const [key, value] of Object.entries(target)) result[key] = value;
  for (const [key, value] of Object.entries(source)) {
    if (key === "__proto__") continue;
    result[key] = value;
  }
  return result;
}

const update = JSON.parse('{"name":"Eve","__proto__":{"admin":true}}');
const profile = patchedMerge({ name: "Alice", role: "user" }, update);

assert.equal(profile.admin, undefined);
assert.equal(Object.hasOwn(profile, "admin"), false);
assert.equal(Object.getPrototypeOf(profile), Object.prototype);
assert.equal({}.admin, undefined);
assert.equal(profile.admin ? "authorized" : "denied", "denied");
console.log(
  "patched Immutable.js merge rejected profile prototype replacement",
);
