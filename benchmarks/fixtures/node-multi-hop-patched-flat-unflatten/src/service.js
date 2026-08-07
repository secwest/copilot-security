import { materializeSettings } from "./storage.js";

export function expandSettings(entries) {
  return materializeSettings(entries);
}
