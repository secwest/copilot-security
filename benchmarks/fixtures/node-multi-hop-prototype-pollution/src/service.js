import { storePreference } from "./storage.js";

export function updatePreference(patch) {
  return storePreference(patch);
}
