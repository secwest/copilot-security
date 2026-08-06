import { findAccount } from "./service.js";

export async function routeAccountLookup(selector) {
  return findAccount(selector);
}
