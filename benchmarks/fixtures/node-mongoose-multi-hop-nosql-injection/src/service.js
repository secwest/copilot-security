import { loadAccount } from "./storage.js";

export async function findAccount(selector) {
  return loadAccount(selector);
}
