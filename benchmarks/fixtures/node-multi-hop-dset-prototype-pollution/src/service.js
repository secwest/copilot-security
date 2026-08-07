import { persistSetting } from "./storage.js";

export function assignSetting(path) {
  return persistSetting(path);
}
