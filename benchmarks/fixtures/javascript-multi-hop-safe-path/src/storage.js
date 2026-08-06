import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const DOCUMENT_ROOT = resolve(import.meta.dirname, "..", "documents");
const DOCUMENTS = Object.freeze({
  welcome: resolve(DOCUMENT_ROOT, "welcome.txt"),
});

export function readDocument(key) {
  const selected = DOCUMENTS[key];
  if (selected === undefined) throw new Error("unknown document");
  return readFile(selected, "utf8");
}
