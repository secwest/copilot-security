import { fetchProfile } from "./storage.js";

export function prepareRequest(source) {
  return fetchProfile(source);
}
