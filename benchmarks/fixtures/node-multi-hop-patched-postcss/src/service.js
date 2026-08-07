import { compileStyle } from "./storage.js";

export function prepareStyle(css) {
  return compileStyle(css);
}
