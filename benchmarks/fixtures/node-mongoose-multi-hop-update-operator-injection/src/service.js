import { persistAccountPatch } from "./storage.js";

export async function updateAccount(patch) {
  return persistAccountPatch(patch);
}
