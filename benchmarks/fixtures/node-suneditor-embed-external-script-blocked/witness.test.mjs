import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

test("reports the installed Embed script gate without executing a payload", async () => {
  const packagePath = require.resolve("suneditor/package.json");
  const packageRoot = new URL(
    ".",
    `file:///${packagePath.replaceAll("\\\\", "/")}`,
  );
  const source = await readFile(
    new URL("src/plugins/modal/embed.js", packageRoot),
    "utf8",
  );
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  const hasDefaultDenyGate =
    source.includes("scriptSrcWhitelist") &&
    source.includes("#isAllowedScriptSrc") &&
    source.includes("continue");
  assert.equal(typeof packageJson.version, "string");
  process.stdout.write(
    `${JSON.stringify({ version: packageJson.version, hasDefaultDenyGate })}\n`,
  );
});
