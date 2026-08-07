import { deleteSetting } from "./storage.js";

export function removeSetting(path) {
  return deleteSetting(path);
}
