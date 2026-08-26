import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createI18n } from "vue-i18n";

const manifest = JSON.parse(
  await readFile(new URL("package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies["vue-i18n"];
const witnessKey = "copilotSecurityFlatJsonWitness";
const messages = JSON.parse(`{"__proto__.${witnessKey}":"bounded"}`);
let thrown;
let inherited;

assert.equal(Object.prototype[witnessKey], undefined);
try {
  createI18n({
    legacy: false,
    flatJson: true,
    messages: { en: messages },
  });
  inherited = Object.prototype[witnessKey];
} catch (error) {
  thrown = error instanceof Error ? error.message : String(error);
  inherited = Object.prototype[witnessKey];
} finally {
  delete Object.prototype[witnessKey];
}

if (version === "9.14.2") {
  assert.equal(thrown, undefined);
  assert.equal(inherited, "bounded");
} else {
  assert.match(thrown ?? "", /unsafe key: __proto__/u);
  assert.equal(inherited, undefined);
}
assert.equal(Object.prototype[witnessKey], undefined);
console.log(JSON.stringify({ version, witnessKey, inherited, thrown }));
