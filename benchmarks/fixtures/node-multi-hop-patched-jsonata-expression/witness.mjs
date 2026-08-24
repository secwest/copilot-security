import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const jsonata = require("jsonata");
const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies.jsonata;
const shouldEscape = version === "2.2.0";
const expression =
  '( $hasOwnProperty := $spread($string); $__proto__ := $constructor; $constructor("return process.version")() )';

let escaped = false;
let value;
let errorCode;
try {
  value = await jsonata(expression).evaluate({});
  escaped = value === process.version;
} catch (error) {
  errorCode = error?.code;
}

assert.equal(escaped, shouldEscape);
if (!shouldEscape) assert.equal(errorCode, "T1006");
process.stdout.write(
  `${JSON.stringify({ version, escaped, value, errorCode })}\n`,
);
