import { storeExport } from "./storage.js";

export function prepareExport(prefix, contents) {
  return storeExport(prefix, contents);
}
