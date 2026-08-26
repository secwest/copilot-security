import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createFormatter } from "pickem";

const manifest = JSON.parse(
  await readFile(
    new URL("node_modules/pickem/package.json", import.meta.url),
    "utf8",
  ),
);
const affected = manifest.version === "1.0.6";
assert.ok(affected || manifest.version === "1.0.7");

test(`pickem ${manifest.version} terminal display boundary`, () => {
  const escape = String.fromCharCode(0x1b);
  const bell = String.fromCharCode(0x07);
  const del = String.fromCharCode(0x7f);
  const c1 = String.fromCharCode(0x9b);
  const marker = Buffer.from(
    "COPILOT_SECURITY_INERT_CLIPBOARD_MARKER",
  ).toString("base64");
  const item = {
    label: `release${escape}]52;c;${marker}${bell}${escape}[1A${escape}[2K${c1}6n${del}`,
    description: `summary${bell}`,
    value: "release-17",
  };
  const rendered = createFormatter()(item, { count: 1, lastUsed: 0 });
  const observed = {
    containsBell: rendered.includes(bell),
    containsC1: rendered.includes(c1),
    containsClipboardMarker: rendered.includes(marker),
    containsDel: rendered.includes(del),
    containsOsc: rendered.includes(`${escape}]`),
  };

  assert.deepEqual(
    observed,
    Object.fromEntries(Object.keys(observed).map((key) => [key, affected])),
  );
  assert.equal(item.value, "release-17");
  console.log(
    JSON.stringify({
      version: manifest.version,
      ...observed,
      returnedValue: item.value,
    }),
  );
});
