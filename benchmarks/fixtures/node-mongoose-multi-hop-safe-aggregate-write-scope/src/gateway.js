import { maintainAccounts } from "./service.js";

export async function routeAccountMaintenance(criteria) {
  return maintainAccounts(criteria);
}
