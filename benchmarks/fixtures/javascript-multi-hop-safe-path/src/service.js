import { readDocument } from "./storage.js";

export function loadDocument(key) {
  return readDocument(key);
}
