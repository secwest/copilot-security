import { compileStatusIndex } from "./storage.js";

export function prepareStatusIndex(status) {
  return compileStatusIndex(status);
}
