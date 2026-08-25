import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { NunjucksRenderer, Prompty } from "@prompty/core";

const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies["@prompty/core"];
const shouldExecute = version === "2.0.0-beta.4";
const renderer = new NunjucksRenderer();
const agent = new Prompty({ name: "witness", model: "fixed" });
const template = '{{ range.constructor("return process.version")() }}';

let value;
let error;
try {
  value = await renderer.render(agent, template, {});
} catch (caught) {
  error = caught instanceof Error ? caught.message : String(caught);
}

const executed = value === process.version;
assert.equal(executed, shouldExecute);
if (!shouldExecute) assert.match(error ?? "", /Unsafe template member access/u);
process.stdout.write(
  `${JSON.stringify({ version, executed, value, error })}\n`,
);
