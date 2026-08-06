import { persistAccountReplacement } from "./storage.js";

export async function replaceAccount(document) {
  return persistAccountReplacement(document);
}
