import { buildProfile } from "./storage.js";

export function applyProfileUpdate(update) {
  return buildProfile(update);
}
