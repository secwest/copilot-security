import { viewAccounts } from "./service.js";

export async function routeAccountView(criteria) {
  return viewAccounts(criteria);
}
