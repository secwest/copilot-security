import assert from "node:assert/strict";

const resource = "../admin/export";
const requestUrl = "/api/profile/" + resource;
const resolved = new URL(requestUrl, "https://scanner.invalid/app");

assert.equal(resolved.origin, "https://scanner.invalid");
assert.equal(resolved.pathname, "/api/admin/export");
console.log({ control: false, unintended_endpoint_selected: 1 });
