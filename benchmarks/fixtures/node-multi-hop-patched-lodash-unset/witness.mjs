import assert from "node:assert/strict";

function toKey(value) {
  return typeof value === "symbol" ? value : String(value);
}

function patchedUnset(object, path) {
  const keys = path.map(toKey);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === "__proto__" && !Object.hasOwn(object, "__proto__")) {
      return false;
    }
    if (
      (key === "constructor" || key === "prototype") &&
      index < keys.length - 1
    ) {
      return false;
    }
  }
  let parent = object;
  for (const key of keys.slice(0, -1)) parent = parent[key];
  return delete parent[keys.at(-1)];
}

const descriptor = Object.getOwnPropertyDescriptor(
  Object.prototype,
  "toString",
);
assert.ok(descriptor);
assert.equal(patchedUnset({}, [["__proto__"], "toString"]), false);
assert.deepEqual(
  Object.getOwnPropertyDescriptor(Object.prototype, "toString"),
  descriptor,
);
assert.equal(String({}), "[object Object]");
console.log("patched Lodash path normalization rejected prototype deletion");
