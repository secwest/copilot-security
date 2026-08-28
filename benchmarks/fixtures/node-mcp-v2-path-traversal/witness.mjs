import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { pathToFileURL } from "node:url";

const temporaryRoot = await mkdtemp(join(tmpdir(), "mcp-path-witness-"));
try {
  const documentRoot = join(temporaryRoot, "documents");
  await mkdir(documentRoot);
  process.env.MCP_DOCUMENT_ROOT = pathToFileURL(documentRoot + sep).href;
  const { saveDocument } = await import("./src/server.mjs");
  const marker = "MCP_PATH_TRAVERSAL_WITNESS_OK";
  await saveDocument("../escaped.txt", marker);
  assert.equal(
    await readFile(join(temporaryRoot, "escaped.txt"), "utf8"),
    marker,
  );
} finally {
  delete process.env.MCP_DOCUMENT_ROOT;
  await rm(temporaryRoot, { recursive: true, force: true });
}
console.log("MCP v2 path witness escaped only a disposable temporary root.");
