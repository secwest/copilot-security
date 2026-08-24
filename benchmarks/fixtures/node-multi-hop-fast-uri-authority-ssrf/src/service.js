import { fetchProfile } from "./storage.js";

export function prepareRequest(reference) {
  return fetchProfile(reference);
}
