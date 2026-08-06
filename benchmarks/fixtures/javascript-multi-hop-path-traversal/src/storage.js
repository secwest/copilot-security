import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const DOCUMENT_ROOT = resolve(import.meta.dirname, "..", "documents");

export function readDocument(name) {
  return readFile(resolve(DOCUMENT_ROOT, name), "utf8");
}
