import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { render } = require("velocityjs");
const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies.velocityjs;
const shouldExecute = version === "2.1.6";
const template =
  '#set($f=$x.constructor.constructor("return process.version"))#set($r=$f())$r';
const value = render(template, { x: {} });
const executed = value === process.version;

assert.equal(executed, shouldExecute);
if (!shouldExecute) assert.equal(value, "$r");
process.stdout.write(`${JSON.stringify({ version, executed, value })}\n`);
