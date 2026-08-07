import assert from "node:assert/strict";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

const root = mkdtempSync(join(tmpdir(), "copilot-security-tmp-witness-"));
const intended = join(root, "tenant-a");
await import("node:fs/promises").then(({ mkdir }) => mkdir(intended));

function vulnerableFileSync(options) {
  const name = `${options.prefix}-12345-random`;
  const path = join(options.tmpdir, name);
  return { fd: openSync(path, "wx"), name: path };
}

try {
  const created = vulnerableFileSync({
    tmpdir: intended,
    prefix: "../tenant-b-export",
  });
  writeFileSync(created.fd, "protected export contents");
  closeSync(created.fd);
  assert.equal(relative(intended, created.name).startsWith(".."), true);
  assert.equal(readFileSync(created.name, "utf8"), "protected export contents");
  console.log("vulnerable tmp prefix directory escape reproduced");
} finally {
  rmSync(root, { recursive: true, force: true });
}
