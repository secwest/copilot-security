import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { expand } from "brace-expansion";

const manifest = JSON.parse(
  await readFile(new URL("package.json", import.meta.url)),
);
const version = manifest.dependencies["brace-expansion"];
const input = `{${"0".repeat(4_000)}1..100000}`;
const started = performance.now();
const output = expand(input);
const elapsedMs = performance.now() - started;
const digest = createHash("sha256").update(output.join("\n")).digest("hex");

assert.equal(output.length, 999);
assert.equal(
  output.reduce((total, value) => total + value.length, 0),
  3_996_999,
);
assert.equal(
  digest,
  "81c8707f87bfc8296e30d5a462fce26265b195b5db6df1160ba7da477f61f8c2",
);
if (version === "5.0.8") {
  assert.ok(elapsedMs >= 400, `vulnerable work completed in ${elapsedMs} ms`);
} else {
  assert.equal(version, "5.0.9");
  assert.ok(elapsedMs < 1_500, `patched work took ${elapsedMs} ms`);
}
console.log(
  `${version} completed the bounded witness in ${elapsedMs.toFixed(3)} ms`,
);
