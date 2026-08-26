import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { renderPage } from "./src/renderer.js";

const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies["@rhinostone/swig"];
const shouldReadOutsideRoot = version === "2.7.0";
let output;
let errorMessage;
try {
  output = renderPage("../secret.txt");
} catch (error) {
  errorMessage = error instanceof Error ? error.message : String(error);
}
const readOutsideRoot = output?.includes("bounded-swig-secret") === true;
assert.equal(readOutsideRoot, shouldReadOutsideRoot);
if (!shouldReadOutsideRoot) {
  assert.match(errorMessage ?? "", /resolves outside the loader root/u);
}
process.stdout.write(
  `${JSON.stringify({ version, readOutsideRoot, output, errorMessage })}\n`,
);
