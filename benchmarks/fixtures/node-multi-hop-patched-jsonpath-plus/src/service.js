import { selectRecords } from "./storage.js";

export function evaluateSelection(path) {
  return selectRecords(path);
}
