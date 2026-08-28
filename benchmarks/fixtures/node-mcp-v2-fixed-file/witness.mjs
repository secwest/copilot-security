import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const temporaryRoot = await mkdtemp(join(tmpdir(), "mcp-fixed-file-witness-"));
try {
  const fixedFile = join(temporaryRoot, "operator-note.txt");
  process.env.MCP_DOCUMENT_FILE = pathToFileURL(fixedFile).href;
  const { saveDocument } = await import("./src/server.mjs");
  await saveDocument("../ignored.txt", "MCP_FIXED_FILE_WITNESS_OK");
  assert.equal(
    await readFile(fixedFile, "utf8"),
    "../ignored.txt:MCP_FIXED_FILE_WITNESS_OK",
  );
} finally {
  delete process.env.MCP_DOCUMENT_FILE;
  await rm(temporaryRoot, { recursive: true, force: true });
}
console.log("MCP v2 fixed-file control kept both tool inputs out of the path.");
