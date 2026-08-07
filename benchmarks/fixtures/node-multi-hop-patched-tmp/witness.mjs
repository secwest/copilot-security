import assert from "node:assert/strict";

function repairedPrefix(prefix) {
  if (prefix.includes("..")) throw new Error("Relative value not allowed");
  return prefix;
}

assert.throws(
  () => repairedPrefix("../tenant-b-export"),
  /Relative value not allowed/u,
);
assert.equal(repairedPrefix("tenant-a-export"), "tenant-a-export");
console.log("patched tmp prefix rejection reproduced");
