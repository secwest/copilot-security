import { updateAccount } from "./service.js";

export async function routeAccountPatch(patch) {
  return updateAccount(patch);
}
