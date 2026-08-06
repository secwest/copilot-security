import { readDocument } from "./storage.js";

export function loadDocument(name) {
  return readDocument(name);
}
