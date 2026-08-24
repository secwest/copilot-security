import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(
  await readFile(new URL("package.json", import.meta.url)),
);
const version = manifest.dependencies.nanoid;
const fixtureRoot = new URL(".", import.meta.url);
const child = spawnSync(
  process.execPath,
  [
    "--input-type=module",
    "--eval",
    'const { issueId } = await import("./src/storage.mjs"); process.stdout.write(JSON.stringify(issueId(-1)));',
  ],
  {
    cwd: fixtureRoot,
    encoding: "utf8",
    killSignal: "SIGKILL",
    timeout: 750,
    windowsHide: true,
  },
);
const timedOut = child.error?.code === "ETIMEDOUT";

if (version === "5.1.15") {
  assert.equal(timedOut, true);
  assert.equal(child.signal, "SIGKILL");
  assert.equal(child.stdout, "");
} else {
  assert.equal(version, "5.1.16");
  assert.equal(timedOut, false);
  assert.equal(child.status, 0);
  assert.equal(child.stdout, '""');
}
console.log(
  JSON.stringify({
    version,
    timedOut,
    status: child.status,
    signal: child.signal,
  }),
);
