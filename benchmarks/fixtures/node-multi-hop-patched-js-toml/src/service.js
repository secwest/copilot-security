import { loadOptions } from "./storage.js";

export function parseDocument(text) {
  return loadOptions(text);
}
