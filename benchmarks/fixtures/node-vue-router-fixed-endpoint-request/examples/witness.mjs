import assert from "node:assert/strict";

const resource = "../admin/export";
const requestUrl = "/api/search?q=" + encodeURIComponent(resource);
const resolved = new URL(requestUrl, "https://scanner.invalid/app");

assert.equal(resolved.origin, "https://scanner.invalid");
assert.equal(resolved.pathname, "/api/search");
assert.equal(resolved.searchParams.get("q"), resource);
console.log({ control: true, fixed_endpoint_preserved: 1 });
